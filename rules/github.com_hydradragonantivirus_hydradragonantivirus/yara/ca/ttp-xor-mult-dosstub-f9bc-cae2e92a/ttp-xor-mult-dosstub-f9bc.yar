rule TTP_XOR_MULT_DOSStub_f9bc {
  strings:
    $key_f9bc = { ad d4 [2] d9 cc [2] 9e ce [2] d9 df [2] 97 d3 [2] 9b d9 [2] 8c d2 [2] 97 9c [2] aa }

  condition:
    any of them
}