rule TTP_XOR_MULT_DOSStub_72bc {
  strings:
    $key_72bc = { 26 d4 [2] 52 cc [2] 15 ce [2] 52 df [2] 1c d3 [2] 10 d9 [2] 07 d2 [2] 1c 9c [2] 21 }

  condition:
    any of them
}