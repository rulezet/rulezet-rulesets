rule TTP_XOR_QUAD_CurrentVersionRun_bfb8 {
  strings:
    $key_bfb8 = { ec d7 [2] c8 d9 [2] e3 f5 [2] cd d7 [2] d9 cc [2] d6 d6 [2] c8 cb [2] ca ca [2] d1 cc [2] cd cb [2] d1 e4 }

  condition:
    any of them
}