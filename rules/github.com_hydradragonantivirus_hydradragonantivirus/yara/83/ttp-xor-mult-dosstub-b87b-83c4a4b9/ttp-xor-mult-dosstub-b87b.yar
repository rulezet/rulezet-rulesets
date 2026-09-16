rule TTP_XOR_MULT_DOSStub_b87b {
  strings:
    $key_b87b = { ec 13 [2] 98 0b [2] df 09 [2] 98 18 [2] d6 14 [2] da 1e [2] cd 15 [2] d6 5b [2] eb }

  condition:
    any of them
}