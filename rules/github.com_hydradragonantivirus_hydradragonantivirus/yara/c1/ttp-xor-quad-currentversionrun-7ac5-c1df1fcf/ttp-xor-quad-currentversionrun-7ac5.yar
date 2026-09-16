rule TTP_XOR_QUAD_CurrentVersionRun_7ac5 {
  strings:
    $key_7ac5 = { 29 aa [2] 0d a4 [2] 26 88 [2] 08 aa [2] 1c b1 [2] 13 ab [2] 0d b6 [2] 0f b7 [2] 14 b1 [2] 08 b6 [2] 14 99 }

  condition:
    any of them
}