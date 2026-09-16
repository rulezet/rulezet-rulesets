rule TTP_XOR_MULT_DOSStub_7cad {
  strings:
    $key_7cad = { 28 c5 [2] 5c dd [2] 1b df [2] 5c ce [2] 12 c2 [2] 1e c8 [2] 09 c3 [2] 12 8d [2] 2f }

  condition:
    any of them
}