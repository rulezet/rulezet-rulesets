rule TTP_XOR_MULT_DOSStub_9b99 {
  strings:
    $key_9b99 = { cf f1 [2] bb e9 [2] fc eb [2] bb fa [2] f5 f6 [2] f9 fc [2] ee f7 [2] f5 b9 [2] c8 }

  condition:
    any of them
}