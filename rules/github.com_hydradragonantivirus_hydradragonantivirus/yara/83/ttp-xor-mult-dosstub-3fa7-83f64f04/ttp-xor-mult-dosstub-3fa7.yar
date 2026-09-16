rule TTP_XOR_MULT_DOSStub_3fa7 {
  strings:
    $key_3fa7 = { 6b cf [2] 1f d7 [2] 58 d5 [2] 1f c4 [2] 51 c8 [2] 5d c2 [2] 4a c9 [2] 51 87 [2] 6c }

  condition:
    any of them
}