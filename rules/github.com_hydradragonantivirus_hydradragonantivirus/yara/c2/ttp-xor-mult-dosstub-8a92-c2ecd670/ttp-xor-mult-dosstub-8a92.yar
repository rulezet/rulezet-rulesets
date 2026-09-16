rule TTP_XOR_MULT_DOSStub_8a92 {
  strings:
    $key_8a92 = { de fa [2] aa e2 [2] ed e0 [2] aa f1 [2] e4 fd [2] e8 f7 [2] ff fc [2] e4 b2 [2] d9 }

  condition:
    any of them
}