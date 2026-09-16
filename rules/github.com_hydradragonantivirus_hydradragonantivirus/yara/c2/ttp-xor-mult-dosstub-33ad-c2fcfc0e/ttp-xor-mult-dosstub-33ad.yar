rule TTP_XOR_MULT_DOSStub_33ad {
  strings:
    $key_33ad = { 67 c5 [2] 13 dd [2] 54 df [2] 13 ce [2] 5d c2 [2] 51 c8 [2] 46 c3 [2] 5d 8d [2] 60 }

  condition:
    any of them
}