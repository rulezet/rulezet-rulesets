rule TTP_XOR_QUAD_CurrentVersionRun_61d5 {
  strings:
    $key_61d5 = { 32 ba [2] 16 b4 [2] 3d 98 [2] 13 ba [2] 07 a1 [2] 08 bb [2] 16 a6 [2] 14 a7 [2] 0f a1 [2] 13 a6 [2] 0f 89 }

  condition:
    any of them
}