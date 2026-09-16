rule TTP_XOR_MULT_DOSStub_5fa7 {
  strings:
    $key_5fa7 = { 0b cf [2] 7f d7 [2] 38 d5 [2] 7f c4 [2] 31 c8 [2] 3d c2 [2] 2a c9 [2] 31 87 [2] 0c }

  condition:
    any of them
}