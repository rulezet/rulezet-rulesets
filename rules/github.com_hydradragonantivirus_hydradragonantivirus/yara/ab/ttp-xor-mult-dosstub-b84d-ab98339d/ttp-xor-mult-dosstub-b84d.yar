rule TTP_XOR_MULT_DOSStub_b84d {
  strings:
    $key_b84d = { ec 25 [2] 98 3d [2] df 3f [2] 98 2e [2] d6 22 [2] da 28 [2] cd 23 [2] d6 6d [2] eb }

  condition:
    any of them
}