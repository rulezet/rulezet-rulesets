rule TTP_XOR_MULT_DOSStub_f7bc {
  strings:
    $key_f7bc = { a3 d4 [2] d7 cc [2] 90 ce [2] d7 df [2] 99 d3 [2] 95 d9 [2] 82 d2 [2] 99 9c [2] a4 }

  condition:
    any of them
}