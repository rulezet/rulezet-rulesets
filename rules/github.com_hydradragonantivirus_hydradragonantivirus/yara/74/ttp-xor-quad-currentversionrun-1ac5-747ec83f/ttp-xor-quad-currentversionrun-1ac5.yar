rule TTP_XOR_QUAD_CurrentVersionRun_1ac5 {
  strings:
    $key_1ac5 = { 49 aa [2] 6d a4 [2] 46 88 [2] 68 aa [2] 7c b1 [2] 73 ab [2] 6d b6 [2] 6f b7 [2] 74 b1 [2] 68 b6 [2] 74 99 }

  condition:
    any of them
}