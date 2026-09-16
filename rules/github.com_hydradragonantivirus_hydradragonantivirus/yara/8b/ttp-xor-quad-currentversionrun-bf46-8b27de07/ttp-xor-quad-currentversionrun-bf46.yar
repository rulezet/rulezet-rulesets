rule TTP_XOR_QUAD_CurrentVersionRun_bf46 {
  strings:
    $key_bf46 = { ec 29 [2] c8 27 [2] e3 0b [2] cd 29 [2] d9 32 [2] d6 28 [2] c8 35 [2] ca 34 [2] d1 32 [2] cd 35 [2] d1 1a }

  condition:
    any of them
}