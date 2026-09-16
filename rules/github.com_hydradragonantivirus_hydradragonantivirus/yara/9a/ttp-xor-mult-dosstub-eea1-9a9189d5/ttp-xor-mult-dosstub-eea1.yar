rule TTP_XOR_MULT_DOSStub_eea1 {
  strings:
    $key_eea1 = { ba c9 [2] ce d1 [2] 89 d3 [2] ce c2 [2] 80 ce [2] 8c c4 [2] 9b cf [2] 80 81 [2] bd }

  condition:
    any of them
}