rule TTP_XOR_MULT_DOSStub_e9bc {
  strings:
    $key_e9bc = { bd d4 [2] c9 cc [2] 8e ce [2] c9 df [2] 87 d3 [2] 8b d9 [2] 9c d2 [2] 87 9c [2] ba }

  condition:
    any of them
}