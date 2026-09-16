rule TTP_XOR_MULT_DOSStub_05ad {
  strings:
    $key_05ad = { 51 c5 [2] 25 dd [2] 62 df [2] 25 ce [2] 6b c2 [2] 67 c8 [2] 70 c3 [2] 6b 8d [2] 56 }

  condition:
    any of them
}