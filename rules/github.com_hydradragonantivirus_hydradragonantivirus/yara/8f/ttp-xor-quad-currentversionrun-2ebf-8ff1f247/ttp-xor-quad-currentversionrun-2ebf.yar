rule TTP_XOR_QUAD_CurrentVersionRun_2ebf {
  strings:
    $key_2ebf = { 7d d0 [2] 59 de [2] 72 f2 [2] 5c d0 [2] 48 cb [2] 47 d1 [2] 59 cc [2] 5b cd [2] 40 cb [2] 5c cc [2] 40 e3 }

  condition:
    any of them
}