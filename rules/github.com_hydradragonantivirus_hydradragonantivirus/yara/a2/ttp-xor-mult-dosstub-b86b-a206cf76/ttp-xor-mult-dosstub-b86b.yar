rule TTP_XOR_MULT_DOSStub_b86b {
  strings:
    $key_b86b = { ec 03 [2] 98 1b [2] df 19 [2] 98 08 [2] d6 04 [2] da 0e [2] cd 05 [2] d6 4b [2] eb }

  condition:
    any of them
}