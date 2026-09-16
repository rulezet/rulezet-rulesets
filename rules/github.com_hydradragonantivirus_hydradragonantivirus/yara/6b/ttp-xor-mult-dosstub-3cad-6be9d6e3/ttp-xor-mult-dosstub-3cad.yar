rule TTP_XOR_MULT_DOSStub_3cad {
  strings:
    $key_3cad = { 68 c5 [2] 1c dd [2] 5b df [2] 1c ce [2] 52 c2 [2] 5e c8 [2] 49 c3 [2] 52 8d [2] 6f }

  condition:
    any of them
}