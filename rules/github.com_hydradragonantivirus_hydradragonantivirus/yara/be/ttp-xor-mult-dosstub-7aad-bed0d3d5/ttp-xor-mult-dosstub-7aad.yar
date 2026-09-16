rule TTP_XOR_MULT_DOSStub_7aad {
  strings:
    $key_7aad = { 2e c5 [2] 5a dd [2] 1d df [2] 5a ce [2] 14 c2 [2] 18 c8 [2] 0f c3 [2] 14 8d [2] 29 }

  condition:
    any of them
}