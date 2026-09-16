rule TTP_XOR_MULT_DOSStub_1ebc {
  strings:
    $key_1ebc = { 4a d4 [2] 3e cc [2] 79 ce [2] 3e df [2] 70 d3 [2] 7c d9 [2] 6b d2 [2] 70 9c [2] 4d }

  condition:
    any of them
}