rule TTP_XOR_MULT_DOSStub_5cad {
  strings:
    $key_5cad = { 08 c5 [2] 7c dd [2] 3b df [2] 7c ce [2] 32 c2 [2] 3e c8 [2] 29 c3 [2] 32 8d [2] 0f }

  condition:
    any of them
}