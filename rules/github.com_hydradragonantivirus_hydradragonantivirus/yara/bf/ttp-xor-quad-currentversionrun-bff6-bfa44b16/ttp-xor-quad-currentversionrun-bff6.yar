rule TTP_XOR_QUAD_CurrentVersionRun_bff6 {
  strings:
    $key_bff6 = { ec 99 [2] c8 97 [2] e3 bb [2] cd 99 [2] d9 82 [2] d6 98 [2] c8 85 [2] ca 84 [2] d1 82 [2] cd 85 [2] d1 aa }

  condition:
    any of them
}