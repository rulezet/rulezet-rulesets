rule TTP_XOR_QUAD_CurrentVersionRun_a353 {
  strings:
    $key_a353 = { f0 3c [2] d4 32 [2] ff 1e [2] d1 3c [2] c5 27 [2] ca 3d [2] d4 20 [2] d6 21 [2] cd 27 [2] d1 20 [2] cd 0f }

  condition:
    any of them
}