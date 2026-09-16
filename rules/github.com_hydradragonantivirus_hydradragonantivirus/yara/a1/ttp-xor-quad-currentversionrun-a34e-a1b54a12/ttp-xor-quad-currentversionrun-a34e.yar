rule TTP_XOR_QUAD_CurrentVersionRun_a34e {
  strings:
    $key_a34e = { f0 21 [2] d4 2f [2] ff 03 [2] d1 21 [2] c5 3a [2] ca 20 [2] d4 3d [2] d6 3c [2] cd 3a [2] d1 3d [2] cd 12 }

  condition:
    any of them
}