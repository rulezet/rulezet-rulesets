rule TTP_XOR_MULT_DOSStub_7b84 {
  strings:
    $key_7b84 = { 2f ec [2] 5b f4 [2] 1c f6 [2] 5b e7 [2] 15 eb [2] 19 e1 [2] 0e ea [2] 15 a4 [2] 28 }

  condition:
    any of them
}