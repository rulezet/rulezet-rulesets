rule TTP_XOR_MULT_DOSStub_4fa0 {
  strings:
    $key_4fa0 = { 1b c8 [2] 6f d0 [2] 28 d2 [2] 6f c3 [2] 21 cf [2] 2d c5 [2] 3a ce [2] 21 80 [2] 1c }

  condition:
    any of them
}