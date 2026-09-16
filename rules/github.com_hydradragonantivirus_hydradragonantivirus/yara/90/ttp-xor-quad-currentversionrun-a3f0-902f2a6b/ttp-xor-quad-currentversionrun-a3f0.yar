rule TTP_XOR_QUAD_CurrentVersionRun_a3f0 {
  strings:
    $key_a3f0 = { f0 9f [2] d4 91 [2] ff bd [2] d1 9f [2] c5 84 [2] ca 9e [2] d4 83 [2] d6 82 [2] cd 84 [2] d1 83 [2] cd ac }

  condition:
    any of them
}