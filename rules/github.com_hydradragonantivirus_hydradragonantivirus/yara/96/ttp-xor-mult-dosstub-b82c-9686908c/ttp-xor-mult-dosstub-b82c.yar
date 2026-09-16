rule TTP_XOR_MULT_DOSStub_b82c {
  strings:
    $key_b82c = { ec 44 [2] 98 5c [2] df 5e [2] 98 4f [2] d6 43 [2] da 49 [2] cd 42 [2] d6 0c [2] eb }

  condition:
    any of them
}