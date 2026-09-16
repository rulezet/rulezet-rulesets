rule TTP_XOR_QUAD_CurrentVersionRun_5abf {
  strings:
    $key_5abf = { 09 d0 [2] 2d de [2] 06 f2 [2] 28 d0 [2] 3c cb [2] 33 d1 [2] 2d cc [2] 2f cd [2] 34 cb [2] 28 cc [2] 34 e3 }

  condition:
    any of them
}