rule TTP_XOR_MULT_DOSStub_e7bc {
  strings:
    $key_e7bc = { b3 d4 [2] c7 cc [2] 80 ce [2] c7 df [2] 89 d3 [2] 85 d9 [2] 92 d2 [2] 89 9c [2] b4 }

  condition:
    any of them
}