rule TTP_XOR_MULT_DOSStub_b8af {
  strings:
    $key_b8af = { ec c7 [2] 98 df [2] df dd [2] 98 cc [2] d6 c0 [2] da ca [2] cd c1 [2] d6 8f [2] eb }

  condition:
    any of them
}