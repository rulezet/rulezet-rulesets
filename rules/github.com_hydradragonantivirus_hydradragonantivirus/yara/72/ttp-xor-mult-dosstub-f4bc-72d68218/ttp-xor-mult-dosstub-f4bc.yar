rule TTP_XOR_MULT_DOSStub_f4bc {
  strings:
    $key_f4bc = { a0 d4 [2] d4 cc [2] 93 ce [2] d4 df [2] 9a d3 [2] 96 d9 [2] 81 d2 [2] 9a 9c [2] a7 }

  condition:
    any of them
}