rule TTP_XOR_MULT_DOSStub_499a {
  strings:
    $key_499a = { 1d f2 [2] 69 ea [2] 2e e8 [2] 69 f9 [2] 27 f5 [2] 2b ff [2] 3c f4 [2] 27 ba [2] 1a }

  condition:
    any of them
}