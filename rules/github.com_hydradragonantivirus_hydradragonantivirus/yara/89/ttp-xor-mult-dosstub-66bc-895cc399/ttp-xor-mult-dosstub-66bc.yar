rule TTP_XOR_MULT_DOSStub_66bc {
  strings:
    $key_66bc = { 32 d4 [2] 46 cc [2] 01 ce [2] 46 df [2] 08 d3 [2] 04 d9 [2] 13 d2 [2] 08 9c [2] 35 }

  condition:
    any of them
}