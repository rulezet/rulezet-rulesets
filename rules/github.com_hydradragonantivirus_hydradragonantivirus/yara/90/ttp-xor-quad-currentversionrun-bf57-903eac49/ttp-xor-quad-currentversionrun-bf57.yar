rule TTP_XOR_QUAD_CurrentVersionRun_bf57 {
  strings:
    $key_bf57 = { ec 38 [2] c8 36 [2] e3 1a [2] cd 38 [2] d9 23 [2] d6 39 [2] c8 24 [2] ca 25 [2] d1 23 [2] cd 24 [2] d1 0b }

  condition:
    any of them
}