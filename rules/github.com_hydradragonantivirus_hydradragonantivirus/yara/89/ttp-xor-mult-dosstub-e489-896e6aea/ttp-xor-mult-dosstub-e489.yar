rule TTP_XOR_MULT_DOSStub_e489 {
  strings:
    $key_e489 = { b0 e1 [2] c4 f9 [2] 83 fb [2] c4 ea [2] 8a e6 [2] 86 ec [2] 91 e7 [2] 8a a9 [2] b7 }

  condition:
    any of them
}