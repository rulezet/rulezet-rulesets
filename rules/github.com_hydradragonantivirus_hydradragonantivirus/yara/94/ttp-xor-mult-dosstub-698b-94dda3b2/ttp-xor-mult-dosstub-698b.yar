rule TTP_XOR_MULT_DOSStub_698b {
  strings:
    $key_698b = { 3d e3 [2] 49 fb [2] 0e f9 [2] 49 e8 [2] 07 e4 [2] 0b ee [2] 1c e5 [2] 07 ab [2] 3a }

  condition:
    any of them
}