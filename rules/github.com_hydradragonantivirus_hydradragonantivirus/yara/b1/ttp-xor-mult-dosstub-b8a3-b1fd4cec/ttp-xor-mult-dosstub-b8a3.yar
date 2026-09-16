rule TTP_XOR_MULT_DOSStub_b8a3 {
  strings:
    $key_b8a3 = { ec cb [2] 98 d3 [2] df d1 [2] 98 c0 [2] d6 cc [2] da c6 [2] cd cd [2] d6 83 [2] eb }

  condition:
    any of them
}