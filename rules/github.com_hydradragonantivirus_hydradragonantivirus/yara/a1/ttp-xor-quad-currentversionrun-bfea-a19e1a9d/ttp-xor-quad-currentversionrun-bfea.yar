rule TTP_XOR_QUAD_CurrentVersionRun_bfea {
  strings:
    $key_bfea = { ec 85 [2] c8 8b [2] e3 a7 [2] cd 85 [2] d9 9e [2] d6 84 [2] c8 99 [2] ca 98 [2] d1 9e [2] cd 99 [2] d1 b6 }

  condition:
    any of them
}