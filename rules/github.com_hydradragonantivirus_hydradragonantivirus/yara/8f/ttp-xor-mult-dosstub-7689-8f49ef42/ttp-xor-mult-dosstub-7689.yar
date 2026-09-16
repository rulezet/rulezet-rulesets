rule TTP_XOR_MULT_DOSStub_7689 {
  strings:
    $key_7689 = { 22 e1 [2] 56 f9 [2] 11 fb [2] 56 ea [2] 18 e6 [2] 14 ec [2] 03 e7 [2] 18 a9 [2] 25 }

  condition:
    any of them
}