rule TTP_XOR_QUAD_CurrentVersionRun_2ac5 {
  strings:
    $key_2ac5 = { 79 aa [2] 5d a4 [2] 76 88 [2] 58 aa [2] 4c b1 [2] 43 ab [2] 5d b6 [2] 5f b7 [2] 44 b1 [2] 58 b6 [2] 44 99 }

  condition:
    any of them
}