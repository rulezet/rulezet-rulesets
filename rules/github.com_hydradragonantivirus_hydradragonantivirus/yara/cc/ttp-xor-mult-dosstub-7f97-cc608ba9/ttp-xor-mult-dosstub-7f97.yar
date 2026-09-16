rule TTP_XOR_MULT_DOSStub_7f97 {
  strings:
    $key_7f97 = { 2b ff [2] 5f e7 [2] 18 e5 [2] 5f f4 [2] 11 f8 [2] 1d f2 [2] 0a f9 [2] 11 b7 [2] 2c }

  condition:
    any of them
}