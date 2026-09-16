rule TTP_XOR_MULT_DOSStub_b821 {
  strings:
    $key_b821 = { ec 49 [2] 98 51 [2] df 53 [2] 98 42 [2] d6 4e [2] da 44 [2] cd 4f [2] d6 01 [2] eb }

  condition:
    any of them
}