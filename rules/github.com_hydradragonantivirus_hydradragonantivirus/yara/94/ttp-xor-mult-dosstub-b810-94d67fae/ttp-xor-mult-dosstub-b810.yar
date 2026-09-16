rule TTP_XOR_MULT_DOSStub_b810 {
  strings:
    $key_b810 = { ec 78 [2] 98 60 [2] df 62 [2] 98 73 [2] d6 7f [2] da 75 [2] cd 7e [2] d6 30 [2] eb }

  condition:
    any of them
}