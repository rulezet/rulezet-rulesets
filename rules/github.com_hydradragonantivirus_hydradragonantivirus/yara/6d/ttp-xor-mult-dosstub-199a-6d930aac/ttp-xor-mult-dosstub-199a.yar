rule TTP_XOR_MULT_DOSStub_199a {
  strings:
    $key_199a = { 4d f2 [2] 39 ea [2] 7e e8 [2] 39 f9 [2] 77 f5 [2] 7b ff [2] 6c f4 [2] 77 ba [2] 4a }

  condition:
    any of them
}