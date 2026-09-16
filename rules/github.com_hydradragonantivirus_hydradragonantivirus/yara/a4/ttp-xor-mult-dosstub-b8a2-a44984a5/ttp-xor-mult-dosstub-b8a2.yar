rule TTP_XOR_MULT_DOSStub_b8a2 {
  strings:
    $key_b8a2 = { ec ca [2] 98 d2 [2] df d0 [2] 98 c1 [2] d6 cd [2] da c7 [2] cd cc [2] d6 82 [2] eb }

  condition:
    any of them
}