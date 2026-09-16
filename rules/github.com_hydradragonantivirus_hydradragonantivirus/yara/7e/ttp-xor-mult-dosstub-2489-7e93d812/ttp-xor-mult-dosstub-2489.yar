rule TTP_XOR_MULT_DOSStub_2489 {
  strings:
    $key_2489 = { 70 e1 [2] 04 f9 [2] 43 fb [2] 04 ea [2] 4a e6 [2] 46 ec [2] 51 e7 [2] 4a a9 [2] 77 }

  condition:
    any of them
}