rule TTP_XOR_QUAD_CurrentVersionRun_29c5 {
  strings:
    $key_29c5 = { 7a aa [2] 5e a4 [2] 75 88 [2] 5b aa [2] 4f b1 [2] 40 ab [2] 5e b6 [2] 5c b7 [2] 47 b1 [2] 5b b6 [2] 47 99 }

  condition:
    any of them
}