rule TTP_XOR_MULT_DOSStub_1e89 {
  strings:
    $key_1e89 = { 4a e1 [2] 3e f9 [2] 79 fb [2] 3e ea [2] 70 e6 [2] 7c ec [2] 6b e7 [2] 70 a9 [2] 4d }

  condition:
    any of them
}