rule TTP_XOR_MULT_DOSStub_4897 {
  strings:
    $key_4897 = { 1c ff [2] 68 e7 [2] 2f e5 [2] 68 f4 [2] 26 f8 [2] 2a f2 [2] 3d f9 [2] 26 b7 [2] 1b }

  condition:
    any of them
}