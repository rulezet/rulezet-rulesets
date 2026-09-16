rule TTP_XOR_MULT_DOSStub_c1bc {
  strings:
    $key_c1bc = { 95 d4 [2] e1 cc [2] a6 ce [2] e1 df [2] af d3 [2] a3 d9 [2] b4 d2 [2] af 9c [2] 92 }

  condition:
    any of them
}