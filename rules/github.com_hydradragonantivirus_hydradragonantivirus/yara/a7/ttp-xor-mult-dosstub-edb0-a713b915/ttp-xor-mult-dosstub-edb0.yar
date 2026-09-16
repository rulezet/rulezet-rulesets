rule TTP_XOR_MULT_DOSStub_edb0 {
  strings:
    $key_edb0 = { b9 d8 [2] cd c0 [2] 8a c2 [2] cd d3 [2] 83 df [2] 8f d5 [2] 98 de [2] 83 90 [2] be }

  condition:
    any of them
}