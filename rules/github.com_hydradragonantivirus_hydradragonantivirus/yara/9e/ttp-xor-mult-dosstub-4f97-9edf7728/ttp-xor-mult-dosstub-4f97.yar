rule TTP_XOR_MULT_DOSStub_4f97 {
  strings:
    $key_4f97 = { 1b ff [2] 6f e7 [2] 28 e5 [2] 6f f4 [2] 21 f8 [2] 2d f2 [2] 3a f9 [2] 21 b7 [2] 1c }

  condition:
    any of them
}