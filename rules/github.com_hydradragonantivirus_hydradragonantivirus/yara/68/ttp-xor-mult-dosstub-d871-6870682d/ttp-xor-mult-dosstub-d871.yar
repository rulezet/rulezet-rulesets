rule TTP_XOR_MULT_DOSStub_d871 {
  strings:
    $key_d871 = { 8c 19 [2] f8 01 [2] bf 03 [2] f8 12 [2] b6 1e [2] ba 14 [2] ad 1f [2] b6 51 [2] 8b }

  condition:
    any of them
}