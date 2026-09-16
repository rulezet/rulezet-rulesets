rule TTP_XOR_MULT_DOSStub_1aac {
  strings:
    $key_1aac = { 4e c4 [2] 3a dc [2] 7d de [2] 3a cf [2] 74 c3 [2] 78 c9 [2] 6f c2 [2] 74 8c [2] 49 }

  condition:
    any of them
}