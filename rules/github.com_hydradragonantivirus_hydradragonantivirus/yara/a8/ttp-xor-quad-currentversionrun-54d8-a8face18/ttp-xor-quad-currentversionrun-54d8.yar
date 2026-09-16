rule TTP_XOR_QUAD_CurrentVersionRun_54d8 {
  strings:
    $key_54d8 = { 07 b7 [2] 23 b9 [2] 08 95 [2] 26 b7 [2] 32 ac [2] 3d b6 [2] 23 ab [2] 21 aa [2] 3a ac [2] 26 ab [2] 3a 84 }

  condition:
    any of them
}