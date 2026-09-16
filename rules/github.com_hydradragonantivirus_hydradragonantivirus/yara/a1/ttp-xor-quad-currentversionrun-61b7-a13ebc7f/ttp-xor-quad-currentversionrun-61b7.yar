rule TTP_XOR_QUAD_CurrentVersionRun_61b7 {
  strings:
    $key_61b7 = { 32 d8 [2] 16 d6 [2] 3d fa [2] 13 d8 [2] 07 c3 [2] 08 d9 [2] 16 c4 [2] 14 c5 [2] 0f c3 [2] 13 c4 [2] 0f eb }

  condition:
    any of them
}