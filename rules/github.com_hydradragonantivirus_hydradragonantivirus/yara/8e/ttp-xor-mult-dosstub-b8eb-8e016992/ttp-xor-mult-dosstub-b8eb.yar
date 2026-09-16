rule TTP_XOR_MULT_DOSStub_b8eb {
  strings:
    $key_b8eb = { ec 83 [2] 98 9b [2] df 99 [2] 98 88 [2] d6 84 [2] da 8e [2] cd 85 [2] d6 cb [2] eb }

  condition:
    any of them
}