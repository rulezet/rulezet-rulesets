rule TTP_XOR_MULT_DOSStub_6990 {
  strings:
    $key_6990 = { 3d f8 [2] 49 e0 [2] 0e e2 [2] 49 f3 [2] 07 ff [2] 0b f5 [2] 1c fe [2] 07 b0 [2] 3a }

  condition:
    any of them
}