rule TTP_XOR_MULT_DOSStub_6aad {
  strings:
    $key_6aad = { 3e c5 [2] 4a dd [2] 0d df [2] 4a ce [2] 04 c2 [2] 08 c8 [2] 1f c3 [2] 04 8d [2] 39 }

  condition:
    any of them
}