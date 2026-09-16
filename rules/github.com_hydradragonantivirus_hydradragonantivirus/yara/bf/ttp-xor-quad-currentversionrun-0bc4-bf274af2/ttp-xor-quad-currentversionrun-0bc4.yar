rule TTP_XOR_QUAD_CurrentVersionRun_0bc4 {
  strings:
    $key_0bc4 = { 58 ab [2] 7c a5 [2] 57 89 [2] 79 ab [2] 6d b0 [2] 62 aa [2] 7c b7 [2] 7e b6 [2] 65 b0 [2] 79 b7 [2] 65 98 }

  condition:
    any of them
}