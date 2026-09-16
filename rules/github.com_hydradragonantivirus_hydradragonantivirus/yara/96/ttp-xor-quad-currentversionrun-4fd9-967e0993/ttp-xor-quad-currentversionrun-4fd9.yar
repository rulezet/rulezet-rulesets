rule TTP_XOR_QUAD_CurrentVersionRun_4fd9 {
  strings:
    $key_4fd9 = { 1c b6 [2] 38 b8 [2] 13 94 [2] 3d b6 [2] 29 ad [2] 26 b7 [2] 38 aa [2] 3a ab [2] 21 ad [2] 3d aa [2] 21 85 }

  condition:
    any of them
}