rule TTP_XOR_MULT_DOSStub_4bbc {
  strings:
    $key_4bbc = { 1f d4 [2] 6b cc [2] 2c ce [2] 6b df [2] 25 d3 [2] 29 d9 [2] 3e d2 [2] 25 9c [2] 18 }

  condition:
    any of them
}