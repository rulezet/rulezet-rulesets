rule TTP_XOR_MULT_DOSStub_fa84 {
  strings:
    $key_fa84 = { ae ec [2] da f4 [2] 9d f6 [2] da e7 [2] 94 eb [2] 98 e1 [2] 8f ea [2] 94 a4 [2] a9 }

  condition:
    any of them
}