rule TTP_XOR_QUAD_CurrentVersionRun_54d9 {
  strings:
    $key_54d9 = { 07 b6 [2] 23 b8 [2] 08 94 [2] 26 b6 [2] 32 ad [2] 3d b7 [2] 23 aa [2] 21 ab [2] 3a ad [2] 26 aa [2] 3a 85 }

  condition:
    any of them
}