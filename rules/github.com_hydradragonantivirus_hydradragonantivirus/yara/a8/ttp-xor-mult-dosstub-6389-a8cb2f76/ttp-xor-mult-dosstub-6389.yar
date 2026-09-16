rule TTP_XOR_MULT_DOSStub_6389 {
  strings:
    $key_6389 = { 37 e1 [2] 43 f9 [2] 04 fb [2] 43 ea [2] 0d e6 [2] 01 ec [2] 16 e7 [2] 0d a9 [2] 30 }

  condition:
    any of them
}