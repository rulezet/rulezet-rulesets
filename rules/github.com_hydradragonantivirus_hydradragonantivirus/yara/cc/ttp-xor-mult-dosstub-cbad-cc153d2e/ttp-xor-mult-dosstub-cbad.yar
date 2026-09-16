rule TTP_XOR_MULT_DOSStub_cbad {
  strings:
    $key_cbad = { 9f c5 [2] eb dd [2] ac df [2] eb ce [2] a5 c2 [2] a9 c8 [2] be c3 [2] a5 8d [2] 98 }

  condition:
    any of them
}