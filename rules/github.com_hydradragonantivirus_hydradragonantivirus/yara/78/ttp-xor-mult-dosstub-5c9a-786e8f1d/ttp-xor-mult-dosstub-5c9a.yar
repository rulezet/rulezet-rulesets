rule TTP_XOR_MULT_DOSStub_5c9a {
  strings:
    $key_5c9a = { 08 f2 [2] 7c ea [2] 3b e8 [2] 7c f9 [2] 32 f5 [2] 3e ff [2] 29 f4 [2] 32 ba [2] 0f }

  condition:
    any of them
}