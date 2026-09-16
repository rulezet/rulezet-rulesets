rule TTP_XOR_QUAD_CurrentVersionRun_bf74 {
  strings:
    $key_bf74 = { ec 1b [2] c8 15 [2] e3 39 [2] cd 1b [2] d9 00 [2] d6 1a [2] c8 07 [2] ca 06 [2] d1 00 [2] cd 07 [2] d1 28 }

  condition:
    any of them
}