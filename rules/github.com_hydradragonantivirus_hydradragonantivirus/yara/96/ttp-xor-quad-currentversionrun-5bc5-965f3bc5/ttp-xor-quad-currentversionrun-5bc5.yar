rule TTP_XOR_QUAD_CurrentVersionRun_5bc5 {
  strings:
    $key_5bc5 = { 08 aa [2] 2c a4 [2] 07 88 [2] 29 aa [2] 3d b1 [2] 32 ab [2] 2c b6 [2] 2e b7 [2] 35 b1 [2] 29 b6 [2] 35 99 }

  condition:
    any of them
}