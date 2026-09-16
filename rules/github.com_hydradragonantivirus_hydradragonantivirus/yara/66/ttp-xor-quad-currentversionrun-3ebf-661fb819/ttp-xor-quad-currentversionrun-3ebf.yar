rule TTP_XOR_QUAD_CurrentVersionRun_3ebf {
  strings:
    $key_3ebf = { 6d d0 [2] 49 de [2] 62 f2 [2] 4c d0 [2] 58 cb [2] 57 d1 [2] 49 cc [2] 4b cd [2] 50 cb [2] 4c cc [2] 50 e3 }

  condition:
    any of them
}