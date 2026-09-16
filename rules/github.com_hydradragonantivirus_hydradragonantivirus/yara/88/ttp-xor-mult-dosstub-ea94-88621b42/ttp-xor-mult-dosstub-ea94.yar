rule TTP_XOR_MULT_DOSStub_ea94 {
  strings:
    $key_ea94 = { be fc [2] ca e4 [2] 8d e6 [2] ca f7 [2] 84 fb [2] 88 f1 [2] 9f fa [2] 84 b4 [2] b9 }

  condition:
    any of them
}