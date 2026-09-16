rule TTP_XOR_MULT_DOSStub_4cad {
  strings:
    $key_4cad = { 18 c5 [2] 6c dd [2] 2b df [2] 6c ce [2] 22 c2 [2] 2e c8 [2] 39 c3 [2] 22 8d [2] 1f }

  condition:
    any of them
}