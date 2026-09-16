rule TTP_XOR_MULT_DOSStub_1189 {
  strings:
    $key_1189 = { 45 e1 [2] 31 f9 [2] 76 fb [2] 31 ea [2] 7f e6 [2] 73 ec [2] 64 e7 [2] 7f a9 [2] 42 }

  condition:
    any of them
}