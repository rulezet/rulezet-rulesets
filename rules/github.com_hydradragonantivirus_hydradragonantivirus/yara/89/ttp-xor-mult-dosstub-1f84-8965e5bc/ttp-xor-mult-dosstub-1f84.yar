rule TTP_XOR_MULT_DOSStub_1f84 {
  strings:
    $key_1f84 = { 4b ec [2] 3f f4 [2] 78 f6 [2] 3f e7 [2] 71 eb [2] 7d e1 [2] 6a ea [2] 71 a4 [2] 4c }

  condition:
    any of them
}