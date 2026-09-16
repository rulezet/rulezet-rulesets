rule TTP_XOR_MULT_DOSStub_ea8b {
  strings:
    $key_ea8b = { be e3 [2] ca fb [2] 8d f9 [2] ca e8 [2] 84 e4 [2] 88 ee [2] 9f e5 [2] 84 ab [2] b9 }

  condition:
    any of them
}