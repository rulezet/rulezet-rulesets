rule TTP_XOR_QUAD_CurrentVersionRun_28bf {
  strings:
    $key_28bf = { 7b d0 [2] 5f de [2] 74 f2 [2] 5a d0 [2] 4e cb [2] 41 d1 [2] 5f cc [2] 5d cd [2] 46 cb [2] 5a cc [2] 46 e3 }

  condition:
    any of them
}