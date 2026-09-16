rule TTP_XOR_MULT_DOSStub_7b89 {
  strings:
    $key_7b89 = { 2f e1 [2] 5b f9 [2] 1c fb [2] 5b ea [2] 15 e6 [2] 19 ec [2] 0e e7 [2] 15 a9 [2] 28 }

  condition:
    any of them
}