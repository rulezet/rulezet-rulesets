rule TTP_XOR_MULT_DOSStub_3b82 {
  strings:
    $key_3b82 = { 6f ea [2] 1b f2 [2] 5c f0 [2] 1b e1 [2] 55 ed [2] 59 e7 [2] 4e ec [2] 55 a2 [2] 68 }

  condition:
    any of them
}