rule TTP_XOR_QUAD_CurrentVersionRun_39c5 {
  strings:
    $key_39c5 = { 6a aa [2] 4e a4 [2] 65 88 [2] 4b aa [2] 5f b1 [2] 50 ab [2] 4e b6 [2] 4c b7 [2] 57 b1 [2] 4b b6 [2] 57 99 }

  condition:
    any of them
}