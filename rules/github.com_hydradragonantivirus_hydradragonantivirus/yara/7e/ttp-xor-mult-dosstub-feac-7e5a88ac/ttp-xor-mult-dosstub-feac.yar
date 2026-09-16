rule TTP_XOR_MULT_DOSStub_feac {
  strings:
    $key_feac = { aa c4 [2] de dc [2] 99 de [2] de cf [2] 90 c3 [2] 9c c9 [2] 8b c2 [2] 90 8c [2] ad }

  condition:
    any of them
}