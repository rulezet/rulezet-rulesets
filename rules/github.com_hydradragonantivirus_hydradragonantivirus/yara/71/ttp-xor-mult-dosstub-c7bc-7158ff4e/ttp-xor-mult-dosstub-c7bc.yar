rule TTP_XOR_MULT_DOSStub_c7bc {
  strings:
    $key_c7bc = { 93 d4 [2] e7 cc [2] a0 ce [2] e7 df [2] a9 d3 [2] a5 d9 [2] b2 d2 [2] a9 9c [2] 94 }

  condition:
    any of them
}