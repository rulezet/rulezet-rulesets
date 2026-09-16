rule TTP_XOR_MULT_DOSStub_f6bc {
  strings:
    $key_f6bc = { a2 d4 [2] d6 cc [2] 91 ce [2] d6 df [2] 98 d3 [2] 94 d9 [2] 83 d2 [2] 98 9c [2] a5 }

  condition:
    any of them
}