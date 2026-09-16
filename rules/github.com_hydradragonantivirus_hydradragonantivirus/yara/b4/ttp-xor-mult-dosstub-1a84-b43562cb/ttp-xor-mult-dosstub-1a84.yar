rule TTP_XOR_MULT_DOSStub_1a84 {
  strings:
    $key_1a84 = { 4e ec [2] 3a f4 [2] 7d f6 [2] 3a e7 [2] 74 eb [2] 78 e1 [2] 6f ea [2] 74 a4 [2] 49 }

  condition:
    any of them
}