rule TTP_XOR_QUAD_CurrentVersionRun_61d4 {
  strings:
    $key_61d4 = { 32 bb [2] 16 b5 [2] 3d 99 [2] 13 bb [2] 07 a0 [2] 08 ba [2] 16 a7 [2] 14 a6 [2] 0f a0 [2] 13 a7 [2] 0f 88 }

  condition:
    any of them
}