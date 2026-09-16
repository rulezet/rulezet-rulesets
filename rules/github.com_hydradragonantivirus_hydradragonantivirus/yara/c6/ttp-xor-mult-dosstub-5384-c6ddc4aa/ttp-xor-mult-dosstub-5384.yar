rule TTP_XOR_MULT_DOSStub_5384 {
  strings:
    $key_5384 = { 07 ec [2] 73 f4 [2] 34 f6 [2] 73 e7 [2] 3d eb [2] 31 e1 [2] 26 ea [2] 3d a4 [2] 00 }

  condition:
    any of them
}