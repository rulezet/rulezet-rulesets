rule TTP_XOR_QUAD_CurrentVersionRun_5bd7 {
  strings:
    $key_5bd7 = { 08 b8 [2] 2c b6 [2] 07 9a [2] 29 b8 [2] 3d a3 [2] 32 b9 [2] 2c a4 [2] 2e a5 [2] 35 a3 [2] 29 a4 [2] 35 8b }

  condition:
    any of them
}