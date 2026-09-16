rule TTP_XOR_MULT_DOSStub_7b82 {
  strings:
    $key_7b82 = { 2f ea [2] 5b f2 [2] 1c f0 [2] 5b e1 [2] 15 ed [2] 19 e7 [2] 0e ec [2] 15 a2 [2] 28 }

  condition:
    any of them
}