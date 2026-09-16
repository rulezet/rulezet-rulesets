rule TTP_XOR_MULT_DOSStub_09bc {
  strings:
    $key_09bc = { 5d d4 [2] 29 cc [2] 6e ce [2] 29 df [2] 67 d3 [2] 6b d9 [2] 7c d2 [2] 67 9c [2] 5a }

  condition:
    any of them
}