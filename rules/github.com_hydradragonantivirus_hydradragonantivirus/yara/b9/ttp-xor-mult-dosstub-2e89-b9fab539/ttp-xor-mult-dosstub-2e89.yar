rule TTP_XOR_MULT_DOSStub_2e89 {
  strings:
    $key_2e89 = { 7a e1 [2] 0e f9 [2] 49 fb [2] 0e ea [2] 40 e6 [2] 4c ec [2] 5b e7 [2] 40 a9 [2] 7d }

  condition:
    any of them
}