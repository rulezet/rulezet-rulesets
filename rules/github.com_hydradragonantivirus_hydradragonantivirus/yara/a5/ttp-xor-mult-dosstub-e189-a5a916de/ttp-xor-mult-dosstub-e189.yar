rule TTP_XOR_MULT_DOSStub_e189 {
  strings:
    $key_e189 = { b5 e1 [2] c1 f9 [2] 86 fb [2] c1 ea [2] 8f e6 [2] 83 ec [2] 94 e7 [2] 8f a9 [2] b2 }

  condition:
    any of them
}