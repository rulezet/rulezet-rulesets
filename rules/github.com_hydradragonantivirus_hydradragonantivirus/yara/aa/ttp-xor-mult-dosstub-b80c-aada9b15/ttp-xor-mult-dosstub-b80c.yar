rule TTP_XOR_MULT_DOSStub_b80c {
  strings:
    $key_b80c = { ec 64 [2] 98 7c [2] df 7e [2] 98 6f [2] d6 63 [2] da 69 [2] cd 62 [2] d6 2c [2] eb }

  condition:
    any of them
}