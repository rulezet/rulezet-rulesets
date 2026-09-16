rule TTP_XOR_QUAD_CurrentVersionRun_71bf {
  strings:
    $key_71bf = { 22 d0 [2] 06 de [2] 2d f2 [2] 03 d0 [2] 17 cb [2] 18 d1 [2] 06 cc [2] 04 cd [2] 1f cb [2] 03 cc [2] 1f e3 }

  condition:
    any of them
}