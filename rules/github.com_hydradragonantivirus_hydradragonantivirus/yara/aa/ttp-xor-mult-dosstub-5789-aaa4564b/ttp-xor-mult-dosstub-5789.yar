rule TTP_XOR_MULT_DOSStub_5789 {
  strings:
    $key_5789 = { 03 e1 [2] 77 f9 [2] 30 fb [2] 77 ea [2] 39 e6 [2] 35 ec [2] 22 e7 [2] 39 a9 [2] 04 }

  condition:
    any of them
}