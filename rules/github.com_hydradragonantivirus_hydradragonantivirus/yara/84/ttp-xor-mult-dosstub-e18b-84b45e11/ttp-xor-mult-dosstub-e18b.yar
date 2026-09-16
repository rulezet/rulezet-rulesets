rule TTP_XOR_MULT_DOSStub_e18b {
  strings:
    $key_e18b = { b5 e3 [2] c1 fb [2] 86 f9 [2] c1 e8 [2] 8f e4 [2] 83 ee [2] 94 e5 [2] 8f ab [2] b2 }

  condition:
    any of them
}