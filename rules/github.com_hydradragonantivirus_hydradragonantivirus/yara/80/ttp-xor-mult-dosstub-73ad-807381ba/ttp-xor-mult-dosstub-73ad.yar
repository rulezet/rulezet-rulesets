rule TTP_XOR_MULT_DOSStub_73ad {
  strings:
    $key_73ad = { 27 c5 [2] 53 dd [2] 14 df [2] 53 ce [2] 1d c2 [2] 11 c8 [2] 06 c3 [2] 1d 8d [2] 20 }

  condition:
    any of them
}