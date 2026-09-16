rule TTP_XOR_MULT_DOSStub_d2bc {
  strings:
    $key_d2bc = { 86 d4 [2] f2 cc [2] b5 ce [2] f2 df [2] bc d3 [2] b0 d9 [2] a7 d2 [2] bc 9c [2] 81 }

  condition:
    any of them
}