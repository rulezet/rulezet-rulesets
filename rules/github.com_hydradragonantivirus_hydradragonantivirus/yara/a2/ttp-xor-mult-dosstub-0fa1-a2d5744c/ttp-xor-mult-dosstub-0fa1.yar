rule TTP_XOR_MULT_DOSStub_0fa1 {
  strings:
    $key_0fa1 = { 5b c9 [2] 2f d1 [2] 68 d3 [2] 2f c2 [2] 61 ce [2] 6d c4 [2] 7a cf [2] 61 81 [2] 5c }

  condition:
    any of them
}