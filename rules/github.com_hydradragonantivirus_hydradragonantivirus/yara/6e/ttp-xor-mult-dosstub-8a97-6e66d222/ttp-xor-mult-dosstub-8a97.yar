rule TTP_XOR_MULT_DOSStub_8a97 {
  strings:
    $key_8a97 = { de ff [2] aa e7 [2] ed e5 [2] aa f4 [2] e4 f8 [2] e8 f2 [2] ff f9 [2] e4 b7 [2] d9 }

  condition:
    any of them
}