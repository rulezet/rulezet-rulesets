rule TTP_XOR_MULT_DOSStub_1cbc {
  strings:
    $key_1cbc = { 48 d4 [2] 3c cc [2] 7b ce [2] 3c df [2] 72 d3 [2] 7e d9 [2] 69 d2 [2] 72 9c [2] 4f }

  condition:
    any of them
}