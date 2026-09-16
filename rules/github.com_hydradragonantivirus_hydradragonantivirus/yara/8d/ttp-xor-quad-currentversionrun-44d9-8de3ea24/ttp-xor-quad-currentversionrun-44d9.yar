rule TTP_XOR_QUAD_CurrentVersionRun_44d9 {
  strings:
    $key_44d9 = { 17 b6 [2] 33 b8 [2] 18 94 [2] 36 b6 [2] 22 ad [2] 2d b7 [2] 33 aa [2] 31 ab [2] 2a ad [2] 36 aa [2] 2a 85 }

  condition:
    any of them
}