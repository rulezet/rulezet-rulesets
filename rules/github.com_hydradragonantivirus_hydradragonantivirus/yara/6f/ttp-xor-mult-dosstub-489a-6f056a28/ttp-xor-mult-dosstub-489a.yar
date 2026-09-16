rule TTP_XOR_MULT_DOSStub_489a {
  strings:
    $key_489a = { 1c f2 [2] 68 ea [2] 2f e8 [2] 68 f9 [2] 26 f5 [2] 2a ff [2] 3d f4 [2] 26 ba [2] 1b }

  condition:
    any of them
}