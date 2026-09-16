rule TTP_XOR_MULT_DOSStub_2b89 {
  strings:
    $key_2b89 = { 7f e1 [2] 0b f9 [2] 4c fb [2] 0b ea [2] 45 e6 [2] 49 ec [2] 5e e7 [2] 45 a9 [2] 78 }

  condition:
    any of them
}