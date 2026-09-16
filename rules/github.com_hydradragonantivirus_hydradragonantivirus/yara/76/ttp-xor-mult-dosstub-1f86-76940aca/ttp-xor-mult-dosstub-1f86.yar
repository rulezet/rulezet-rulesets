rule TTP_XOR_MULT_DOSStub_1f86 {
  strings:
    $key_1f86 = { 4b ee [2] 3f f6 [2] 78 f4 [2] 3f e5 [2] 71 e9 [2] 7d e3 [2] 6a e8 [2] 71 a6 [2] 4c }

  condition:
    any of them
}