rule TTP_XOR_MULT_DOSStub_bca7 {
  strings:
    $key_bca7 = { e8 cf [2] 9c d7 [2] db d5 [2] 9c c4 [2] d2 c8 [2] de c2 [2] c9 c9 [2] d2 87 [2] ef }

  condition:
    any of them
}