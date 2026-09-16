rule TTP_XOR_QUAD_CurrentVersionRun_5bd9 {
  strings:
    $key_5bd9 = { 08 b6 [2] 2c b8 [2] 07 94 [2] 29 b6 [2] 3d ad [2] 32 b7 [2] 2c aa [2] 2e ab [2] 35 ad [2] 29 aa [2] 35 85 }

  condition:
    any of them
}