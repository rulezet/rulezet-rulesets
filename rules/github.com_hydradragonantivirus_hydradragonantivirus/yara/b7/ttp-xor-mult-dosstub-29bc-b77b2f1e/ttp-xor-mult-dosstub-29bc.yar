rule TTP_XOR_MULT_DOSStub_29bc {
  strings:
    $key_29bc = { 7d d4 [2] 09 cc [2] 4e ce [2] 09 df [2] 47 d3 [2] 4b d9 [2] 5c d2 [2] 47 9c [2] 7a }

  condition:
    any of them
}