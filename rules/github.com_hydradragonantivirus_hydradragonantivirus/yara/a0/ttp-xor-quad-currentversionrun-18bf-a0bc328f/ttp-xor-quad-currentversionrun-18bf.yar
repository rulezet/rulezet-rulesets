rule TTP_XOR_QUAD_CurrentVersionRun_18bf {
  strings:
    $key_18bf = { 4b d0 [2] 6f de [2] 44 f2 [2] 6a d0 [2] 7e cb [2] 71 d1 [2] 6f cc [2] 6d cd [2] 76 cb [2] 6a cc [2] 76 e3 }

  condition:
    any of them
}