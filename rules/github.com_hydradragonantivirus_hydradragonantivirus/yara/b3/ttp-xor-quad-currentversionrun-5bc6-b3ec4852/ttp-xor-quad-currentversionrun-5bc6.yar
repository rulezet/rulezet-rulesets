rule TTP_XOR_QUAD_CurrentVersionRun_5bc6 {
  strings:
    $key_5bc6 = { 08 a9 [2] 2c a7 [2] 07 8b [2] 29 a9 [2] 3d b2 [2] 32 a8 [2] 2c b5 [2] 2e b4 [2] 35 b2 [2] 29 b5 [2] 35 9a }

  condition:
    any of them
}