rule TTP_XOR_QUAD_CurrentVersionRun_bf67 {
  strings:
    $key_bf67 = { ec 08 [2] c8 06 [2] e3 2a [2] cd 08 [2] d9 13 [2] d6 09 [2] c8 14 [2] ca 15 [2] d1 13 [2] cd 14 [2] d1 3b }

  condition:
    any of them
}