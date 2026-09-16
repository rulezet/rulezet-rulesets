rule TTP_XOR_MULT_DOSStub_e789 {
  strings:
    $key_e789 = { b3 e1 [2] c7 f9 [2] 80 fb [2] c7 ea [2] 89 e6 [2] 85 ec [2] 92 e7 [2] 89 a9 [2] b4 }

  condition:
    any of them
}