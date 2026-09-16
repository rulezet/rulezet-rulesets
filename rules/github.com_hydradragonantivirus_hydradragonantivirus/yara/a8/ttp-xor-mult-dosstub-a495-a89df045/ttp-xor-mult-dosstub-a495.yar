rule TTP_XOR_MULT_DOSStub_a495 {
  strings:
    $key_a495 = { f0 fd [2] 84 e5 [2] c3 e7 [2] 84 f6 [2] ca fa [2] c6 f0 [2] d1 fb [2] ca b5 [2] f7 }

  condition:
    any of them
}