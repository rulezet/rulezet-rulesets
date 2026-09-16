rule TTP_XOR_MULT_DOSStub_6b89 {
  strings:
    $key_6b89 = { 3f e1 [2] 4b f9 [2] 0c fb [2] 4b ea [2] 05 e6 [2] 09 ec [2] 1e e7 [2] 05 a9 [2] 38 }

  condition:
    any of them
}