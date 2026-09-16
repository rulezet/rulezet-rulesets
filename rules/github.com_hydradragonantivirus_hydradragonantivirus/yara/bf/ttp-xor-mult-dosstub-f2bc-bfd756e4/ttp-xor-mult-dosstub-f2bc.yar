rule TTP_XOR_MULT_DOSStub_f2bc {
  strings:
    $key_f2bc = { a6 d4 [2] d2 cc [2] 95 ce [2] d2 df [2] 9c d3 [2] 90 d9 [2] 87 d2 [2] 9c 9c [2] a1 }

  condition:
    any of them
}