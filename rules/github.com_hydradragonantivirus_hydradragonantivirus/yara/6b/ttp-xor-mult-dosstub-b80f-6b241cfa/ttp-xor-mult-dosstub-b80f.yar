rule TTP_XOR_MULT_DOSStub_b80f {
  strings:
    $key_b80f = { ec 67 [2] 98 7f [2] df 7d [2] 98 6c [2] d6 60 [2] da 6a [2] cd 61 [2] d6 2f [2] eb }

  condition:
    any of them
}