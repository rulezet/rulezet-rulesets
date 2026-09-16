rule TTP_XOR_MULT_DOSStub_e089 {
  strings:
    $key_e089 = { b4 e1 [2] c0 f9 [2] 87 fb [2] c0 ea [2] 8e e6 [2] 82 ec [2] 95 e7 [2] 8e a9 [2] b3 }

  condition:
    any of them
}