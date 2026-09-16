rule TTP_XOR_QUAD_CurrentVersionRun_bff5 {
  strings:
    $key_bff5 = { ec 9a [2] c8 94 [2] e3 b8 [2] cd 9a [2] d9 81 [2] d6 9b [2] c8 86 [2] ca 87 [2] d1 81 [2] cd 86 [2] d1 a9 }

  condition:
    any of them
}