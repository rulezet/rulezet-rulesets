rule TTP_XOR_MULT_DOSStub_5aad {
  strings:
    $key_5aad = { 0e c5 [2] 7a dd [2] 3d df [2] 7a ce [2] 34 c2 [2] 38 c8 [2] 2f c3 [2] 34 8d [2] 09 }

  condition:
    any of them
}