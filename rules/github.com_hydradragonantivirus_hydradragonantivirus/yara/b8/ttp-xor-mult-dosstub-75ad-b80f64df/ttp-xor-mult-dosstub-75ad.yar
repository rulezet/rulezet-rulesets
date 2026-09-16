rule TTP_XOR_MULT_DOSStub_75ad {
  strings:
    $key_75ad = { 21 c5 [2] 55 dd [2] 12 df [2] 55 ce [2] 1b c2 [2] 17 c8 [2] 00 c3 [2] 1b 8d [2] 26 }

  condition:
    any of them
}