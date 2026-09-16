rule TTP_XOR_MULT_DOSStub_1bbc {
  strings:
    $key_1bbc = { 4f d4 [2] 3b cc [2] 7c ce [2] 3b df [2] 75 d3 [2] 79 d9 [2] 6e d2 [2] 75 9c [2] 48 }

  condition:
    any of them
}