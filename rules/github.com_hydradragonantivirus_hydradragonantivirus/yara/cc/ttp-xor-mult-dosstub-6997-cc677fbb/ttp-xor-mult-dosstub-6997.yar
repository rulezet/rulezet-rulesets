rule TTP_XOR_MULT_DOSStub_6997 {
  strings:
    $key_6997 = { 3d ff [2] 49 e7 [2] 0e e5 [2] 49 f4 [2] 07 f8 [2] 0b f2 [2] 1c f9 [2] 07 b7 [2] 3a }

  condition:
    any of them
}