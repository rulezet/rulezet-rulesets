rule TTP_XOR_MULT_DOSStub_3789 {
  strings:
    $key_3789 = { 63 e1 [2] 17 f9 [2] 50 fb [2] 17 ea [2] 59 e6 [2] 55 ec [2] 42 e7 [2] 59 a9 [2] 64 }

  condition:
    any of them
}