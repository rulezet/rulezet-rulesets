rule TTP_XOR_MULT_DOSStub_588b {
  strings:
    $key_588b = { 0c e3 [2] 78 fb [2] 3f f9 [2] 78 e8 [2] 36 e4 [2] 3a ee [2] 2d e5 [2] 36 ab [2] 0b }

  condition:
    any of them
}