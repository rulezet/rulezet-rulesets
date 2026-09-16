rule TTP_XOR_MULT_DOSStub_2c9a {
  strings:
    $key_2c9a = { 78 f2 [2] 0c ea [2] 4b e8 [2] 0c f9 [2] 42 f5 [2] 4e ff [2] 59 f4 [2] 42 ba [2] 7f }

  condition:
    any of them
}