rule TTP_XOR_MULT_DOSStub_34ad {
  strings:
    $key_34ad = { 60 c5 [2] 14 dd [2] 53 df [2] 14 ce [2] 5a c2 [2] 56 c8 [2] 41 c3 [2] 5a 8d [2] 67 }

  condition:
    any of them
}