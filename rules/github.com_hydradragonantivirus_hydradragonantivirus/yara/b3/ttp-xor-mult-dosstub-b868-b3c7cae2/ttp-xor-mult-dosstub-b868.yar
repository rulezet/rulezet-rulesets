rule TTP_XOR_MULT_DOSStub_b868 {
  strings:
    $key_b868 = { ec 00 [2] 98 18 [2] df 1a [2] 98 0b [2] d6 07 [2] da 0d [2] cd 06 [2] d6 48 [2] eb }

  condition:
    any of them
}