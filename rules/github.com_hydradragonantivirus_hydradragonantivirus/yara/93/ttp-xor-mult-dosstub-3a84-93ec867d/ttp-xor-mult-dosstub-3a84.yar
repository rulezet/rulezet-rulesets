rule TTP_XOR_MULT_DOSStub_3a84 {
  strings:
    $key_3a84 = { 6e ec [2] 1a f4 [2] 5d f6 [2] 1a e7 [2] 54 eb [2] 58 e1 [2] 4f ea [2] 54 a4 [2] 69 }

  condition:
    any of them
}