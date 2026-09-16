rule TTP_XOR_MULT_DOSStub_2f84 {
  strings:
    $key_2f84 = { 7b ec [2] 0f f4 [2] 48 f6 [2] 0f e7 [2] 41 eb [2] 4d e1 [2] 5a ea [2] 41 a4 [2] 7c }

  condition:
    any of them
}