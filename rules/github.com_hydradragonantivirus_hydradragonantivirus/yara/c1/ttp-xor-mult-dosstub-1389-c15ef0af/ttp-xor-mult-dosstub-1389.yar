rule TTP_XOR_MULT_DOSStub_1389 {
  strings:
    $key_1389 = { 47 e1 [2] 33 f9 [2] 74 fb [2] 33 ea [2] 7d e6 [2] 71 ec [2] 66 e7 [2] 7d a9 [2] 40 }

  condition:
    any of them
}