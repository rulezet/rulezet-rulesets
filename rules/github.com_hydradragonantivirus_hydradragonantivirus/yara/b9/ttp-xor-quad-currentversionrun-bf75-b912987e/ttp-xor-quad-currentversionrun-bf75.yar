rule TTP_XOR_QUAD_CurrentVersionRun_bf75 {
  strings:
    $key_bf75 = { ec 1a [2] c8 14 [2] e3 38 [2] cd 1a [2] d9 01 [2] d6 1b [2] c8 06 [2] ca 07 [2] d1 01 [2] cd 06 [2] d1 29 }

  condition:
    any of them
}