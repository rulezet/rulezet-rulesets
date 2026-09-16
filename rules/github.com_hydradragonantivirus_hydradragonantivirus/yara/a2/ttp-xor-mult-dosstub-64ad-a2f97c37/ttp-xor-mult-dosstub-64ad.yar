rule TTP_XOR_MULT_DOSStub_64ad {
  strings:
    $key_64ad = { 30 c5 [2] 44 dd [2] 03 df [2] 44 ce [2] 0a c2 [2] 06 c8 [2] 11 c3 [2] 0a 8d [2] 37 }

  condition:
    any of them
}