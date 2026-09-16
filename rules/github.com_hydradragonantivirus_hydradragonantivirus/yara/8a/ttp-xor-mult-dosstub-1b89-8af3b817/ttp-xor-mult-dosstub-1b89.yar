rule TTP_XOR_MULT_DOSStub_1b89 {
  strings:
    $key_1b89 = { 4f e1 [2] 3b f9 [2] 7c fb [2] 3b ea [2] 75 e6 [2] 79 ec [2] 6e e7 [2] 75 a9 [2] 48 }

  condition:
    any of them
}