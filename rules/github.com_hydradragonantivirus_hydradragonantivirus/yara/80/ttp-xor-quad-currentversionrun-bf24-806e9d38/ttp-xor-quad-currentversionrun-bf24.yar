rule TTP_XOR_QUAD_CurrentVersionRun_bf24 {
  strings:
    $key_bf24 = { ec 4b [2] c8 45 [2] e3 69 [2] cd 4b [2] d9 50 [2] d6 4a [2] c8 57 [2] ca 56 [2] d1 50 [2] cd 57 [2] d1 78 }

  condition:
    any of them
}