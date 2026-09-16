rule TTP_XOR_MULT_DOSStub_b839 {
  strings:
    $key_b839 = { ec 51 [2] 98 49 [2] df 4b [2] 98 5a [2] d6 56 [2] da 5c [2] cd 57 [2] d6 19 [2] eb }

  condition:
    any of them
}