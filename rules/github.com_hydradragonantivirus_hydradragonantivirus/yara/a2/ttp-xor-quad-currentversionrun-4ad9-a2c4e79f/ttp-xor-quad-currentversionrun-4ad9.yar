rule TTP_XOR_QUAD_CurrentVersionRun_4ad9 {
  strings:
    $key_4ad9 = { 19 b6 [2] 3d b8 [2] 16 94 [2] 38 b6 [2] 2c ad [2] 23 b7 [2] 3d aa [2] 3f ab [2] 24 ad [2] 38 aa [2] 24 85 }

  condition:
    any of them
}