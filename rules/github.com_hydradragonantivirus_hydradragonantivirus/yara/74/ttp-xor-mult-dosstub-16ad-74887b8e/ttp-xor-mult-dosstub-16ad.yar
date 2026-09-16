rule TTP_XOR_MULT_DOSStub_16ad {
  strings:
    $key_16ad = { 42 c5 [2] 36 dd [2] 71 df [2] 36 ce [2] 78 c2 [2] 74 c8 [2] 63 c3 [2] 78 8d [2] 45 }

  condition:
    any of them
}