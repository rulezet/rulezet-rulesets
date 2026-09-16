rule TTP_XOR_QUAD_CurrentVersionRun_a35e {
  strings:
    $key_a35e = { f0 31 [2] d4 3f [2] ff 13 [2] d1 31 [2] c5 2a [2] ca 30 [2] d4 2d [2] d6 2c [2] cd 2a [2] d1 2d [2] cd 02 }

  condition:
    any of them
}