rule TTP_XOR_MULT_DOSStub_4aad {
  strings:
    $key_4aad = { 1e c5 [2] 6a dd [2] 2d df [2] 6a ce [2] 24 c2 [2] 28 c8 [2] 3f c3 [2] 24 8d [2] 19 }

  condition:
    any of them
}