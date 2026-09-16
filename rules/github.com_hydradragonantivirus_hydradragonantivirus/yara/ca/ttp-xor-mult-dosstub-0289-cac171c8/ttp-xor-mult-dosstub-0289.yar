rule TTP_XOR_MULT_DOSStub_0289 {
  strings:
    $key_0289 = { 56 e1 [2] 22 f9 [2] 65 fb [2] 22 ea [2] 6c e6 [2] 60 ec [2] 77 e7 [2] 6c a9 [2] 51 }

  condition:
    any of them
}