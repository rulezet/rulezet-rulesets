rule TTP_XOR_MULT_DOSStub_2d97 {
  strings:
    $key_2d97 = { 79 ff [2] 0d e7 [2] 4a e5 [2] 0d f4 [2] 43 f8 [2] 4f f2 [2] 58 f9 [2] 43 b7 [2] 7e }

  condition:
    any of them
}