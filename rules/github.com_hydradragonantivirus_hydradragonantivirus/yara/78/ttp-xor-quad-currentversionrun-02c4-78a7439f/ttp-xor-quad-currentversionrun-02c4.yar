rule TTP_XOR_QUAD_CurrentVersionRun_02c4 {
  strings:
    $key_02c4 = { 51 ab [2] 75 a5 [2] 5e 89 [2] 70 ab [2] 64 b0 [2] 6b aa [2] 75 b7 [2] 77 b6 [2] 6c b0 [2] 70 b7 [2] 6c 98 }

  condition:
    any of them
}