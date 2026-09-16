rule TTP_XOR_QUAD_CurrentVersionRun_61a7 {
  strings:
    $key_61a7 = { 32 c8 [2] 16 c6 [2] 3d ea [2] 13 c8 [2] 07 d3 [2] 08 c9 [2] 16 d4 [2] 14 d5 [2] 0f d3 [2] 13 d4 [2] 0f fb }

  condition:
    any of them
}