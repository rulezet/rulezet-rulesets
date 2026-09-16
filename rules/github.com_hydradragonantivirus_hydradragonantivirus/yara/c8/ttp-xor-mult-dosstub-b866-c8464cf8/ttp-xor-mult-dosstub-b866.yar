rule TTP_XOR_MULT_DOSStub_b866 {
  strings:
    $key_b866 = { ec 0e [2] 98 16 [2] df 14 [2] 98 05 [2] d6 09 [2] da 03 [2] cd 08 [2] d6 46 [2] eb }

  condition:
    any of them
}