rule TTP_XOR_MULT_DOSStub_3bbc {
  strings:
    $key_3bbc = { 6f d4 [2] 1b cc [2] 5c ce [2] 1b df [2] 55 d3 [2] 59 d9 [2] 4e d2 [2] 55 9c [2] 68 }

  condition:
    any of them
}