rule TTP_XOR_MULT_DOSStub_7aac {
  strings:
    $key_7aac = { 2e c4 [2] 5a dc [2] 1d de [2] 5a cf [2] 14 c3 [2] 18 c9 [2] 0f c2 [2] 14 8c [2] 29 }

  condition:
    any of them
}