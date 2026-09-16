rule TTP_XOR_QUAD_CurrentVersionRun_16c4 {
  strings:
    $key_16c4 = { 45 ab [2] 61 a5 [2] 4a 89 [2] 64 ab [2] 70 b0 [2] 7f aa [2] 61 b7 [2] 63 b6 [2] 78 b0 [2] 64 b7 [2] 78 98 }

  condition:
    any of them
}