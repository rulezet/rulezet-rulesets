rule TTP_XOR_MULT_DOSStub_2a97 {
  strings:
    $key_2a97 = { 7e ff [2] 0a e7 [2] 4d e5 [2] 0a f4 [2] 44 f8 [2] 48 f2 [2] 5f f9 [2] 44 b7 [2] 79 }

  condition:
    any of them
}