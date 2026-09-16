rule TTP_XOR_MULT_DOSStub_d888 {
  strings:
    $key_d888 = { 8c e0 [2] f8 f8 [2] bf fa [2] f8 eb [2] b6 e7 [2] ba ed [2] ad e6 [2] b6 a8 [2] 8b }

  condition:
    any of them
}