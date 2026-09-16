rule TTP_XOR_MULT_DOSStub_9b94 {
  strings:
    $key_9b94 = { cf fc [2] bb e4 [2] fc e6 [2] bb f7 [2] f5 fb [2] f9 f1 [2] ee fa [2] f5 b4 [2] c8 }

  condition:
    any of them
}