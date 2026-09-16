rule TTP_XOR_QUAD_CurrentVersionRun_23bb {
  strings:
    $key_23bb = { 70 d4 [2] 54 da [2] 7f f6 [2] 51 d4 [2] 45 cf [2] 4a d5 [2] 54 c8 [2] 56 c9 [2] 4d cf [2] 51 c8 [2] 4d e7 }

  condition:
    any of them
}