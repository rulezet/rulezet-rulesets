rule TTP_XOR_MULT_DOSStub_5fa1 {
  strings:
    $key_5fa1 = { 0b c9 [2] 7f d1 [2] 38 d3 [2] 7f c2 [2] 31 ce [2] 3d c4 [2] 2a cf [2] 31 81 [2] 0c }

  condition:
    any of them
}