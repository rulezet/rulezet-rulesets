rule TTP_XOR_MULT_DOSStub_699a {
  strings:
    $key_699a = { 3d f2 [2] 49 ea [2] 0e e8 [2] 49 f9 [2] 07 f5 [2] 0b ff [2] 1c f4 [2] 07 ba [2] 3a }

  condition:
    any of them
}