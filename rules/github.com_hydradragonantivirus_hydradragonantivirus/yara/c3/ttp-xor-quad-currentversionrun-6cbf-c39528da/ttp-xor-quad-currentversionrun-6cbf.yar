rule TTP_XOR_QUAD_CurrentVersionRun_6cbf {
  strings:
    $key_6cbf = { 3f d0 [2] 1b de [2] 30 f2 [2] 1e d0 [2] 0a cb [2] 05 d1 [2] 1b cc [2] 19 cd [2] 02 cb [2] 1e cc [2] 02 e3 }

  condition:
    any of them
}