rule TTP_XOR_QUAD_CurrentVersionRun_a342 {
  strings:
    $key_a342 = { f0 2d [2] d4 23 [2] ff 0f [2] d1 2d [2] c5 36 [2] ca 2c [2] d4 31 [2] d6 30 [2] cd 36 [2] d1 31 [2] cd 1e }

  condition:
    any of them
}