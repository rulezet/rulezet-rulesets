rule TTP_XOR_MULT_DOSStub_3aac {
  strings:
    $key_3aac = { 6e c4 [2] 1a dc [2] 5d de [2] 1a cf [2] 54 c3 [2] 58 c9 [2] 4f c2 [2] 54 8c [2] 69 }

  condition:
    any of them
}