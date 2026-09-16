rule TTP_XOR_MULT_DOSStub_6f97 {
  strings:
    $key_6f97 = { 3b ff [2] 4f e7 [2] 08 e5 [2] 4f f4 [2] 01 f8 [2] 0d f2 [2] 1a f9 [2] 01 b7 [2] 3c }

  condition:
    any of them
}