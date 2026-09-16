rule TTP_XOR_MULT_DOSStub_6aac {
  strings:
    $key_6aac = { 3e c4 [2] 4a dc [2] 0d de [2] 4a cf [2] 04 c3 [2] 08 c9 [2] 1f c2 [2] 04 8c [2] 39 }

  condition:
    any of them
}