rule TTP_XOR_MULT_DOSStub_d899 {
  strings:
    $key_d899 = { 8c f1 [2] f8 e9 [2] bf eb [2] f8 fa [2] b6 f6 [2] ba fc [2] ad f7 [2] b6 b9 [2] 8b }

  condition:
    any of them
}