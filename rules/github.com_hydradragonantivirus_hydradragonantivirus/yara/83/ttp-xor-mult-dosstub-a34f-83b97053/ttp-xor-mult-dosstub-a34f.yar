rule TTP_XOR_MULT_DOSStub_a34f {
  strings:
    $key_a34f = { f7 27 [2] 83 3f [2] c4 3d [2] 83 2c [2] cd 20 [2] c1 2a [2] d6 21 [2] cd 6f [2] f0 }

  condition:
    any of them
}