rule TTP_XOR_QUAD_CurrentVersionRun_70bf {
  strings:
    $key_70bf = { 23 d0 [2] 07 de [2] 2c f2 [2] 02 d0 [2] 16 cb [2] 19 d1 [2] 07 cc [2] 05 cd [2] 1e cb [2] 02 cc [2] 1e e3 }

  condition:
    any of them
}