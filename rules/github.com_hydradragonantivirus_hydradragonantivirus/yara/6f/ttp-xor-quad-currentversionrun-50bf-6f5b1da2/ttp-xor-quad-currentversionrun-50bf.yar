rule TTP_XOR_QUAD_CurrentVersionRun_50bf {
  strings:
    $key_50bf = { 03 d0 [2] 27 de [2] 0c f2 [2] 22 d0 [2] 36 cb [2] 39 d1 [2] 27 cc [2] 25 cd [2] 3e cb [2] 22 cc [2] 3e e3 }

  condition:
    any of them
}