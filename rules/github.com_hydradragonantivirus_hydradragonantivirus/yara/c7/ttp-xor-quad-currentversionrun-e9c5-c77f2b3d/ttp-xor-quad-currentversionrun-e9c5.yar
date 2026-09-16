rule TTP_XOR_QUAD_CurrentVersionRun_e9c5 {
  strings:
    $key_e9c5 = { ba aa [2] 9e a4 [2] b5 88 [2] 9b aa [2] 8f b1 [2] 80 ab [2] 9e b6 [2] 9c b7 [2] 87 b1 [2] 9b b6 [2] 87 99 }

  condition:
    any of them
}