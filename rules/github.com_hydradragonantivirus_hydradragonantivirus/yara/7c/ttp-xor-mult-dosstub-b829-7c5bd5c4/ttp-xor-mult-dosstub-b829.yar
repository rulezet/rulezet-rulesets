rule TTP_XOR_MULT_DOSStub_b829 {
  strings:
    $key_b829 = { ec 41 [2] 98 59 [2] df 5b [2] 98 4a [2] d6 46 [2] da 4c [2] cd 47 [2] d6 09 [2] eb }

  condition:
    any of them
}