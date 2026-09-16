rule TTP_XOR_MULT_DOSStub_5a84 {
  strings:
    $key_5a84 = { 0e ec [2] 7a f4 [2] 3d f6 [2] 7a e7 [2] 34 eb [2] 38 e1 [2] 2f ea [2] 34 a4 [2] 09 }

  condition:
    any of them
}