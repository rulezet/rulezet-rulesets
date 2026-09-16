rule TTP_XOR_MULT_DOSStub_eca9 {
  strings:
    $key_eca9 = { b8 c1 [2] cc d9 [2] 8b db [2] cc ca [2] 82 c6 [2] 8e cc [2] 99 c7 [2] 82 89 [2] bf }

  condition:
    any of them
}