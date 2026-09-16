rule TTP_XOR_MULT_DOSStub_41ad {
  strings:
    $key_41ad = { 15 c5 [2] 61 dd [2] 26 df [2] 61 ce [2] 2f c2 [2] 23 c8 [2] 34 c3 [2] 2f 8d [2] 12 }

  condition:
    any of them
}