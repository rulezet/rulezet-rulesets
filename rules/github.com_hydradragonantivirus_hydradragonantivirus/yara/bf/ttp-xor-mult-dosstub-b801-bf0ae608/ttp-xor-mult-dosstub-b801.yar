rule TTP_XOR_MULT_DOSStub_b801 {
  strings:
    $key_b801 = { ec 69 [2] 98 71 [2] df 73 [2] 98 62 [2] d6 6e [2] da 64 [2] cd 6f [2] d6 21 [2] eb }

  condition:
    any of them
}