rule TTP_XOR_QUAD_CurrentVersionRun_a3eb {
  strings:
    $key_a3eb = { f0 84 [2] d4 8a [2] ff a6 [2] d1 84 [2] c5 9f [2] ca 85 [2] d4 98 [2] d6 99 [2] cd 9f [2] d1 98 [2] cd b7 }

  condition:
    any of them
}