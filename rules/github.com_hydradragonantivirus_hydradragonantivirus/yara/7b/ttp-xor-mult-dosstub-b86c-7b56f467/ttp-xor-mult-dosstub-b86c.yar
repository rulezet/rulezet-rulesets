rule TTP_XOR_MULT_DOSStub_b86c {
  strings:
    $key_b86c = { ec 04 [2] 98 1c [2] df 1e [2] 98 0f [2] d6 03 [2] da 09 [2] cd 02 [2] d6 4c [2] eb }

  condition:
    any of them
}