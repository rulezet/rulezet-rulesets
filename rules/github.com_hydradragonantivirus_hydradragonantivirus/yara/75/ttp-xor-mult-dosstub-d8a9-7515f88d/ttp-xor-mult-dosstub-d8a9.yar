rule TTP_XOR_MULT_DOSStub_d8a9 {
  strings:
    $key_d8a9 = { 8c c1 [2] f8 d9 [2] bf db [2] f8 ca [2] b6 c6 [2] ba cc [2] ad c7 [2] b6 89 [2] 8b }

  condition:
    any of them
}