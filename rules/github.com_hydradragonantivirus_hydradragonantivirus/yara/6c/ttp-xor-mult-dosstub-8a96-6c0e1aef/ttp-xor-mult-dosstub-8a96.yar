rule TTP_XOR_MULT_DOSStub_8a96 {
  strings:
    $key_8a96 = { de fe [2] aa e6 [2] ed e4 [2] aa f5 [2] e4 f9 [2] e8 f3 [2] ff f8 [2] e4 b6 [2] d9 }

  condition:
    any of them
}