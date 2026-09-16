rule TTP_XOR_QUAD_CurrentVersionRun_bff9 {
  strings:
    $key_bff9 = { ec 96 [2] c8 98 [2] e3 b4 [2] cd 96 [2] d9 8d [2] d6 97 [2] c8 8a [2] ca 8b [2] d1 8d [2] cd 8a [2] d1 a5 }

  condition:
    any of them
}