rule TTP_XOR_MULT_DOSStub_b807 {
  strings:
    $key_b807 = { ec 6f [2] 98 77 [2] df 75 [2] 98 64 [2] d6 68 [2] da 62 [2] cd 69 [2] d6 27 [2] eb }

  condition:
    any of them
}