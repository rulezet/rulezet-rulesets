rule TTP_XOR_MULT_DOSStub_b83d {
  strings:
    $key_b83d = { ec 55 [2] 98 4d [2] df 4f [2] 98 5e [2] d6 52 [2] da 58 [2] cd 53 [2] d6 1d [2] eb }

  condition:
    any of them
}