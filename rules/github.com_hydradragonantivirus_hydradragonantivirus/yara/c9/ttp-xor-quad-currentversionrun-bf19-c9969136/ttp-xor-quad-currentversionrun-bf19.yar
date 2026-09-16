rule TTP_XOR_QUAD_CurrentVersionRun_bf19 {
  strings:
    $key_bf19 = { ec 76 [2] c8 78 [2] e3 54 [2] cd 76 [2] d9 6d [2] d6 77 [2] c8 6a [2] ca 6b [2] d1 6d [2] cd 6a [2] d1 45 }

  condition:
    any of them
}