rule TTP_XOR_MULT_DOSStub_3c9a {
  strings:
    $key_3c9a = { 68 f2 [2] 1c ea [2] 5b e8 [2] 1c f9 [2] 52 f5 [2] 5e ff [2] 49 f4 [2] 52 ba [2] 6f }

  condition:
    any of them
}