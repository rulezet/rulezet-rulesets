rule TTP_XOR_MULT_DOSStub_8a90 {
  strings:
    $key_8a90 = { de f8 [2] aa e0 [2] ed e2 [2] aa f3 [2] e4 ff [2] e8 f5 [2] ff fe [2] e4 b0 [2] d9 }

  condition:
    any of them
}