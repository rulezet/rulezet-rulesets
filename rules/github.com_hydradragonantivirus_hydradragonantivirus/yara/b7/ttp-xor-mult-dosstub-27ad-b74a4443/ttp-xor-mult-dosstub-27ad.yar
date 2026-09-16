rule TTP_XOR_MULT_DOSStub_27ad {
  strings:
    $key_27ad = { 73 c5 [2] 07 dd [2] 40 df [2] 07 ce [2] 49 c2 [2] 45 c8 [2] 52 c3 [2] 49 8d [2] 74 }

  condition:
    any of them
}