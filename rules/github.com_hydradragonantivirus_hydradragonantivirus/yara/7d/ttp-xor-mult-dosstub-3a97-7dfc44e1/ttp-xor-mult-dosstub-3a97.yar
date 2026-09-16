rule TTP_XOR_MULT_DOSStub_3a97 {
  strings:
    $key_3a97 = { 6e ff [2] 1a e7 [2] 5d e5 [2] 1a f4 [2] 54 f8 [2] 58 f2 [2] 4f f9 [2] 54 b7 [2] 69 }

  condition:
    any of them
}