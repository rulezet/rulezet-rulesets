rule TTP_XOR_MULT_DOSStub_3fa1 {
  strings:
    $key_3fa1 = { 6b c9 [2] 1f d1 [2] 58 d3 [2] 1f c2 [2] 51 ce [2] 5d c4 [2] 4a cf [2] 51 81 [2] 6c }

  condition:
    any of them
}