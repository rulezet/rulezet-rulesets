rule TTP_XOR_MULT_DOSStub_d801 {
  strings:
    $key_d801 = { 8c 69 [2] f8 71 [2] bf 73 [2] f8 62 [2] b6 6e [2] ba 64 [2] ad 6f [2] b6 21 [2] 8b }

  condition:
    any of them
}