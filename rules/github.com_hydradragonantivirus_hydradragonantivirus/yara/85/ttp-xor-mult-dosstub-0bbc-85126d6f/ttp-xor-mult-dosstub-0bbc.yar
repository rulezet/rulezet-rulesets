rule TTP_XOR_MULT_DOSStub_0bbc {
  strings:
    $key_0bbc = { 5f d4 [2] 2b cc [2] 6c ce [2] 2b df [2] 65 d3 [2] 69 d9 [2] 7e d2 [2] 65 9c [2] 58 }

  condition:
    any of them
}