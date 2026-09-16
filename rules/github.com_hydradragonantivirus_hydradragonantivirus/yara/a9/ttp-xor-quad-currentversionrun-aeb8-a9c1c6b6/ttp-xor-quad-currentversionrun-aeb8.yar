rule TTP_XOR_QUAD_CurrentVersionRun_aeb8 {
  strings:
    $key_aeb8 = { fd d7 [2] d9 d9 [2] f2 f5 [2] dc d7 [2] c8 cc [2] c7 d6 [2] d9 cb [2] db ca [2] c0 cc [2] dc cb [2] c0 e4 }

  condition:
    any of them
}