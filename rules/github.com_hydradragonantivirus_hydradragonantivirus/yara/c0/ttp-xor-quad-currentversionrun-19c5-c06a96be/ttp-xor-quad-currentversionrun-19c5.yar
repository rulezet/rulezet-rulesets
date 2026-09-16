rule TTP_XOR_QUAD_CurrentVersionRun_19c5 {
  strings:
    $key_19c5 = { 4a aa [2] 6e a4 [2] 45 88 [2] 6b aa [2] 7f b1 [2] 70 ab [2] 6e b6 [2] 6c b7 [2] 77 b1 [2] 6b b6 [2] 77 99 }

  condition:
    any of them
}