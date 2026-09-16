rule TTP_XOR_MULT_DOSStub_b84f {
  strings:
    $key_b84f = { ec 27 [2] 98 3f [2] df 3d [2] 98 2c [2] d6 20 [2] da 2a [2] cd 21 [2] d6 6f [2] eb }

  condition:
    any of them
}