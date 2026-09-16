rule TTP_XOR_QUAD_CurrentVersionRun_bf44 {
  strings:
    $key_bf44 = { ec 2b [2] c8 25 [2] e3 09 [2] cd 2b [2] d9 30 [2] d6 2a [2] c8 37 [2] ca 36 [2] d1 30 [2] cd 37 [2] d1 18 }

  condition:
    any of them
}