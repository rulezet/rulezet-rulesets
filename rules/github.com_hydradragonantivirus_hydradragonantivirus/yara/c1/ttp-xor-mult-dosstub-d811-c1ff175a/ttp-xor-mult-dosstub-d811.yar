rule TTP_XOR_MULT_DOSStub_d811 {
  strings:
    $key_d811 = { 8c 79 [2] f8 61 [2] bf 63 [2] f8 72 [2] b6 7e [2] ba 74 [2] ad 7f [2] b6 31 [2] 8b }

  condition:
    any of them
}