rule TTP_XOR_QUAD_CurrentVersionRun_48bf {
  strings:
    $key_48bf = { 1b d0 [2] 3f de [2] 14 f2 [2] 3a d0 [2] 2e cb [2] 21 d1 [2] 3f cc [2] 3d cd [2] 26 cb [2] 3a cc [2] 26 e3 }

  condition:
    any of them
}