rule TTP_XOR_MULT_DOSStub_1b84 {
  strings:
    $key_1b84 = { 4f ec [2] 3b f4 [2] 7c f6 [2] 3b e7 [2] 75 eb [2] 79 e1 [2] 6e ea [2] 75 a4 [2] 48 }

  condition:
    any of them
}