rule TTP_XOR_QUAD_CurrentVersionRun_bf79 {
  strings:
    $key_bf79 = { ec 16 [2] c8 18 [2] e3 34 [2] cd 16 [2] d9 0d [2] d6 17 [2] c8 0a [2] ca 0b [2] d1 0d [2] cd 0a [2] d1 25 }

  condition:
    any of them
}