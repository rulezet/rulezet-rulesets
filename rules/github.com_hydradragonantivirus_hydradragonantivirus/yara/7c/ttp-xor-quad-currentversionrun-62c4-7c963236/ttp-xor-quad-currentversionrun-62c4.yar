rule TTP_XOR_QUAD_CurrentVersionRun_62c4 {
  strings:
    $key_62c4 = { 31 ab [2] 15 a5 [2] 3e 89 [2] 10 ab [2] 04 b0 [2] 0b aa [2] 15 b7 [2] 17 b6 [2] 0c b0 [2] 10 b7 [2] 0c 98 }

  condition:
    any of them
}