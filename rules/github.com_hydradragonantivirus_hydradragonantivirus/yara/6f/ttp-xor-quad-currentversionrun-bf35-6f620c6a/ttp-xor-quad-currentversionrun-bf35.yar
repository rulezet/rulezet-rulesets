rule TTP_XOR_QUAD_CurrentVersionRun_bf35 {
  strings:
    $key_bf35 = { ec 5a [2] c8 54 [2] e3 78 [2] cd 5a [2] d9 41 [2] d6 5b [2] c8 46 [2] ca 47 [2] d1 41 [2] cd 46 [2] d1 69 }

  condition:
    any of them
}