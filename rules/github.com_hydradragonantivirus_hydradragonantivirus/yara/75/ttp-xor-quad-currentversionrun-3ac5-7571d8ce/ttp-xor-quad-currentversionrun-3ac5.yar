rule TTP_XOR_QUAD_CurrentVersionRun_3ac5 {
  strings:
    $key_3ac5 = { 69 aa [2] 4d a4 [2] 66 88 [2] 48 aa [2] 5c b1 [2] 53 ab [2] 4d b6 [2] 4f b7 [2] 54 b1 [2] 48 b6 [2] 54 99 }

  condition:
    any of them
}