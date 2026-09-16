rule TTP_XOR_QUAD_CurrentVersionRun_bff8 {
  strings:
    $key_bff8 = { ec 97 [2] c8 99 [2] e3 b5 [2] cd 97 [2] d9 8c [2] d6 96 [2] c8 8b [2] ca 8a [2] d1 8c [2] cd 8b [2] d1 a4 }

  condition:
    any of them
}