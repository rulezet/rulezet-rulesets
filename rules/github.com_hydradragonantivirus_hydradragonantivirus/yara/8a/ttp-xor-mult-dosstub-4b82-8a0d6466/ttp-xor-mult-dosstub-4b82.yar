rule TTP_XOR_MULT_DOSStub_4b82 {
  strings:
    $key_4b82 = { 1f ea [2] 6b f2 [2] 2c f0 [2] 6b e1 [2] 25 ed [2] 29 e7 [2] 3e ec [2] 25 a2 [2] 18 }

  condition:
    any of them
}