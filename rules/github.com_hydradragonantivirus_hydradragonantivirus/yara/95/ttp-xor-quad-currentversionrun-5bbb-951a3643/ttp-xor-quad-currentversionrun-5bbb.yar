rule TTP_XOR_QUAD_CurrentVersionRun_5bbb {
  strings:
    $key_5bbb = { 08 d4 [2] 2c da [2] 07 f6 [2] 29 d4 [2] 3d cf [2] 32 d5 [2] 2c c8 [2] 2e c9 [2] 35 cf [2] 29 c8 [2] 35 e7 }

  condition:
    any of them
}