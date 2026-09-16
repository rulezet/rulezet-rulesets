rule TTP_XOR_QUAD_CurrentVersionRun_6ec7 {
  strings:
    $key_6ec7 = { 3d a8 [2] 19 a6 [2] 32 8a [2] 1c a8 [2] 08 b3 [2] 07 a9 [2] 19 b4 [2] 1b b5 [2] 00 b3 [2] 1c b4 [2] 00 9b }

  condition:
    any of them
}