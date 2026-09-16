rule TTP_XOR_QUAD_CurrentVersionRun_2ac4 {
  strings:
    $key_2ac4 = { 79 ab [2] 5d a5 [2] 76 89 [2] 58 ab [2] 4c b0 [2] 43 aa [2] 5d b7 [2] 5f b6 [2] 44 b0 [2] 58 b7 [2] 44 98 }

  condition:
    any of them
}