rule TTP_XOR_QUAD_CurrentVersionRun_32c4 {
  strings:
    $key_32c4 = { 61 ab [2] 45 a5 [2] 6e 89 [2] 40 ab [2] 54 b0 [2] 5b aa [2] 45 b7 [2] 47 b6 [2] 5c b0 [2] 40 b7 [2] 5c 98 }

  condition:
    any of them
}