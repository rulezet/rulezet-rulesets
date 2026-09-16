rule TTP_XOR_MULT_DOSStub_b800 {
  strings:
    $key_b800 = { ec 68 [2] 98 70 [2] df 72 [2] 98 63 [2] d6 6f [2] da 65 [2] cd 6e [2] d6 20 [2] eb }

  condition:
    any of them
}