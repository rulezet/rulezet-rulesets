rule TTP_XOR_MULT_DOSStub_868b {
  strings:
    $key_868b = { d2 e3 [2] a6 fb [2] e1 f9 [2] a6 e8 [2] e8 e4 [2] e4 ee [2] f3 e5 [2] e8 ab [2] d5 }

  condition:
    any of them
}