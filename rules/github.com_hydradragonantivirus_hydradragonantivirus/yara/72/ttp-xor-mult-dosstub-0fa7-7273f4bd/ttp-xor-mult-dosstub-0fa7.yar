rule TTP_XOR_MULT_DOSStub_0fa7 {
  strings:
    $key_0fa7 = { 5b cf [2] 2f d7 [2] 68 d5 [2] 2f c4 [2] 61 c8 [2] 6d c2 [2] 7a c9 [2] 61 87 [2] 5c }

  condition:
    any of them
}