rule TTP_XOR_MULT_DOSStub_10ad {
  strings:
    $key_10ad = { 44 c5 [2] 30 dd [2] 77 df [2] 30 ce [2] 7e c2 [2] 72 c8 [2] 65 c3 [2] 7e 8d [2] 43 }

  condition:
    any of them
}