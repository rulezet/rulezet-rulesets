rule TTP_XOR_QUAD_CurrentVersionRun_bfb5 {
  strings:
    $key_bfb5 = { ec da [2] c8 d4 [2] e3 f8 [2] cd da [2] d9 c1 [2] d6 db [2] c8 c6 [2] ca c7 [2] d1 c1 [2] cd c6 [2] d1 e9 }

  condition:
    any of them
}