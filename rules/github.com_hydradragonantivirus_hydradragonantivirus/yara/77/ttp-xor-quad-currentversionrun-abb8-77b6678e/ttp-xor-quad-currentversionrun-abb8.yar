rule TTP_XOR_QUAD_CurrentVersionRun_abb8 {
  strings:
    $key_abb8 = { f8 d7 [2] dc d9 [2] f7 f5 [2] d9 d7 [2] cd cc [2] c2 d6 [2] dc cb [2] de ca [2] c5 cc [2] d9 cb [2] c5 e4 }

  condition:
    any of them
}