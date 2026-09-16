rule TTP_XOR_MULT_DOSStub_b8ce {
  strings:
    $key_b8ce = { ec a6 [2] 98 be [2] df bc [2] 98 ad [2] d6 a1 [2] da ab [2] cd a0 [2] d6 ee [2] eb }

  condition:
    any of them
}