rule TTP_XOR_MULT_DOSStub_aa4f {
  strings:
    $key_aa4f = { fe 27 [2] 8a 3f [2] cd 3d [2] 8a 2c [2] c4 20 [2] c8 2a [2] df 21 [2] c4 6f [2] f9 }

  condition:
    any of them
}