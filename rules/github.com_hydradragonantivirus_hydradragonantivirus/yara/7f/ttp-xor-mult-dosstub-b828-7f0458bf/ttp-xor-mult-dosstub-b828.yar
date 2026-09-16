rule TTP_XOR_MULT_DOSStub_b828 {
  strings:
    $key_b828 = { ec 40 [2] 98 58 [2] df 5a [2] 98 4b [2] d6 47 [2] da 4d [2] cd 46 [2] d6 08 [2] eb }

  condition:
    any of them
}