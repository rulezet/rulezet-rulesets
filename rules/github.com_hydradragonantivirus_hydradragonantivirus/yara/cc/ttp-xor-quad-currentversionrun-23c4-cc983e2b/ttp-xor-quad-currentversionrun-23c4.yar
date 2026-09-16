rule TTP_XOR_QUAD_CurrentVersionRun_23c4 {
  strings:
    $key_23c4 = { 70 ab [2] 54 a5 [2] 7f 89 [2] 51 ab [2] 45 b0 [2] 4a aa [2] 54 b7 [2] 56 b6 [2] 4d b0 [2] 51 b7 [2] 4d 98 }

  condition:
    any of them
}