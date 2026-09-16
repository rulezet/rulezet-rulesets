rule TTP_XOR_MULT_DOSStub_b838 {
  strings:
    $key_b838 = { ec 50 [2] 98 48 [2] df 4a [2] 98 5b [2] d6 57 [2] da 5d [2] cd 56 [2] d6 18 [2] eb }

  condition:
    any of them
}