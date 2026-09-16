rule TTP_XOR_QUAD_CurrentVersionRun_a349 {
  strings:
    $key_a349 = { f0 26 [2] d4 28 [2] ff 04 [2] d1 26 [2] c5 3d [2] ca 27 [2] d4 3a [2] d6 3b [2] cd 3d [2] d1 3a [2] cd 15 }

  condition:
    any of them
}