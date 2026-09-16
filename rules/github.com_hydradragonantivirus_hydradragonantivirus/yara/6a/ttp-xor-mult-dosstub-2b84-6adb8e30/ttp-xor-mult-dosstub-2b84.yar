rule TTP_XOR_MULT_DOSStub_2b84 {
  strings:
    $key_2b84 = { 7f ec [2] 0b f4 [2] 4c f6 [2] 0b e7 [2] 45 eb [2] 49 e1 [2] 5e ea [2] 45 a4 [2] 78 }

  condition:
    any of them
}