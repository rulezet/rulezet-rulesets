rule TTP_XOR_MULT_DOSStub_b861 {
  strings:
    $key_b861 = { ec 09 [2] 98 11 [2] df 13 [2] 98 02 [2] d6 0e [2] da 04 [2] cd 0f [2] d6 41 [2] eb }

  condition:
    any of them
}