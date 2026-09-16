rule TTP_XOR_QUAD_CurrentVersionRun_6ed9 {
  strings:
    $key_6ed9 = { 3d b6 [2] 19 b8 [2] 32 94 [2] 1c b6 [2] 08 ad [2] 07 b7 [2] 19 aa [2] 1b ab [2] 00 ad [2] 1c aa [2] 00 85 }

  condition:
    any of them
}