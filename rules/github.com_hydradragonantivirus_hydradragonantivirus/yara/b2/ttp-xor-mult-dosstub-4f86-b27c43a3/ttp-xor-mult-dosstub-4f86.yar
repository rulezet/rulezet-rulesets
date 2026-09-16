rule TTP_XOR_MULT_DOSStub_4f86 {
  strings:
    $key_4f86 = { 1b ee [2] 6f f6 [2] 28 f4 [2] 6f e5 [2] 21 e9 [2] 2d e3 [2] 3a e8 [2] 21 a6 [2] 1c }

  condition:
    any of them
}