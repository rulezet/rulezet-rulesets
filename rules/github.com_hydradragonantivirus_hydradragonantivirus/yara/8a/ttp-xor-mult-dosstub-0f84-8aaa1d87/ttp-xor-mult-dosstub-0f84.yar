rule TTP_XOR_MULT_DOSStub_0f84 {
  strings:
    $key_0f84 = { 5b ec [2] 2f f4 [2] 68 f6 [2] 2f e7 [2] 61 eb [2] 6d e1 [2] 7a ea [2] 61 a4 [2] 5c }

  condition:
    any of them
}