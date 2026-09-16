rule TTP_XOR_MULT_DOSStub_a589 {
  strings:
    $key_a589 = { f1 e1 [2] 85 f9 [2] c2 fb [2] 85 ea [2] cb e6 [2] c7 ec [2] d0 e7 [2] cb a9 [2] f6 }

  condition:
    any of them
}