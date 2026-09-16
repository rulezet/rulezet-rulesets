rule TTP_XOR_MULT_DOSStub_6991 {
  strings:
    $key_6991 = { 3d f9 [2] 49 e1 [2] 0e e3 [2] 49 f2 [2] 07 fe [2] 0b f4 [2] 1c ff [2] 07 b1 [2] 3a }

  condition:
    any of them
}