rule TTP_XOR_MULT_DOSStub_b295 {
  strings:
    $key_b295 = { e6 fd [2] 92 e5 [2] d5 e7 [2] 92 f6 [2] dc fa [2] d0 f0 [2] c7 fb [2] dc b5 [2] e1 }

  condition:
    any of them
}