rule TTP_XOR_MULT_DOSStub_6983 {
  strings:
    $key_6983 = { 3d eb [2] 49 f3 [2] 0e f1 [2] 49 e0 [2] 07 ec [2] 0b e6 [2] 1c ed [2] 07 a3 [2] 3a }

  condition:
    any of them
}