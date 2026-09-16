rule TTP_XOR_QUAD_CurrentVersionRun_5ebf {
  strings:
    $key_5ebf = { 0d d0 [2] 29 de [2] 02 f2 [2] 2c d0 [2] 38 cb [2] 37 d1 [2] 29 cc [2] 2b cd [2] 30 cb [2] 2c cc [2] 30 e3 }

  condition:
    any of them
}