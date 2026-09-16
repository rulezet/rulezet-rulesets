rule TTP_XOR_MULT_DOSStub_d887 {
  strings:
    $key_d887 = { 8c ef [2] f8 f7 [2] bf f5 [2] f8 e4 [2] b6 e8 [2] ba e2 [2] ad e9 [2] b6 a7 [2] 8b }

  condition:
    any of them
}