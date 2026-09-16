rule TTP_XOR_MULT_DOSStub_3389 {
  strings:
    $key_3389 = { 67 e1 [2] 13 f9 [2] 54 fb [2] 13 ea [2] 5d e6 [2] 51 ec [2] 46 e7 [2] 5d a9 [2] 60 }

  condition:
    any of them
}