rule TTP_XOR_MULT_DOSStub_c6bc {
  strings:
    $key_c6bc = { 92 d4 [2] e6 cc [2] a1 ce [2] e6 df [2] a8 d3 [2] a4 d9 [2] b3 d2 [2] a8 9c [2] 95 }

  condition:
    any of them
}