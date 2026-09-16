rule TTP_XOR_MULT_DOSStub_0889 {
  strings:
    $key_0889 = { 5c e1 [2] 28 f9 [2] 6f fb [2] 28 ea [2] 66 e6 [2] 6a ec [2] 7d e7 [2] 66 a9 [2] 5b }

  condition:
    any of them
}