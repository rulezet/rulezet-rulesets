rule TTP_XOR_MULT_DOSStub_239b {
  strings:
    $key_239b = { 77 f3 [2] 03 eb [2] 44 e9 [2] 03 f8 [2] 4d f4 [2] 41 fe [2] 56 f5 [2] 4d bb [2] 70 }

  condition:
    any of them
}