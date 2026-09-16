rule TTP_XOR_MULT_DOSStub_15ad {
  strings:
    $key_15ad = { 41 c5 [2] 35 dd [2] 72 df [2] 35 ce [2] 7b c2 [2] 77 c8 [2] 60 c3 [2] 7b 8d [2] 46 }

  condition:
    any of them
}