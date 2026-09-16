rule TTP_XOR_MULT_DOSStub_54ad {
  strings:
    $key_54ad = { 00 c5 [2] 74 dd [2] 33 df [2] 74 ce [2] 3a c2 [2] 36 c8 [2] 21 c3 [2] 3a 8d [2] 07 }

  condition:
    any of them
}