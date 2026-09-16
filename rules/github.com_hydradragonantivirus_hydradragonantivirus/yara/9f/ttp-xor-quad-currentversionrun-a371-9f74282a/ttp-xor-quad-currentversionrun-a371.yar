rule TTP_XOR_QUAD_CurrentVersionRun_a371 {
  strings:
    $key_a371 = { f0 1e [2] d4 10 [2] ff 3c [2] d1 1e [2] c5 05 [2] ca 1f [2] d4 02 [2] d6 03 [2] cd 05 [2] d1 02 [2] cd 2d }

  condition:
    any of them
}