rule TTP_XOR_QUAD_CurrentVersionRun_78bf {
  strings:
    $key_78bf = { 2b d0 [2] 0f de [2] 24 f2 [2] 0a d0 [2] 1e cb [2] 11 d1 [2] 0f cc [2] 0d cd [2] 16 cb [2] 0a cc [2] 16 e3 }

  condition:
    any of them
}