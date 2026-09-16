rule TTP_XOR_MULT_DOSStub_b867 {
  strings:
    $key_b867 = { ec 0f [2] 98 17 [2] df 15 [2] 98 04 [2] d6 08 [2] da 02 [2] cd 09 [2] d6 47 [2] eb }

  condition:
    any of them
}