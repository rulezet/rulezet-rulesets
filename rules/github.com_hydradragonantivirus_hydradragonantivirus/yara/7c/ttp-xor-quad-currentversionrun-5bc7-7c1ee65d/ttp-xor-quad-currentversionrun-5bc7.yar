rule TTP_XOR_QUAD_CurrentVersionRun_5bc7 {
  strings:
    $key_5bc7 = { 08 a8 [2] 2c a6 [2] 07 8a [2] 29 a8 [2] 3d b3 [2] 32 a9 [2] 2c b4 [2] 2e b5 [2] 35 b3 [2] 29 b4 [2] 35 9b }

  condition:
    any of them
}