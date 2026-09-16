rule TTP_XOR_MULT_DOSStub_ed4f {
  strings:
    $key_ed4f = { b9 27 [2] cd 3f [2] 8a 3d [2] cd 2c [2] 83 20 [2] 8f 2a [2] 98 21 [2] 83 6f [2] be }

  condition:
    any of them
}