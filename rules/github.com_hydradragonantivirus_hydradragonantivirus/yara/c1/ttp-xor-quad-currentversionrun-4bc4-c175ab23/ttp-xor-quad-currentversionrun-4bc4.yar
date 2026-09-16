rule TTP_XOR_QUAD_CurrentVersionRun_4bc4 {
  strings:
    $key_4bc4 = { 18 ab [2] 3c a5 [2] 17 89 [2] 39 ab [2] 2d b0 [2] 22 aa [2] 3c b7 [2] 3e b6 [2] 25 b0 [2] 39 b7 [2] 25 98 }

  condition:
    any of them
}