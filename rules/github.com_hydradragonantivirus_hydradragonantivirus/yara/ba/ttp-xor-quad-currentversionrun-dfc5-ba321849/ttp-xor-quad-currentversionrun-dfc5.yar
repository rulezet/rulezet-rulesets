rule TTP_XOR_QUAD_CurrentVersionRun_dfc5 {
  strings:
    $key_dfc5 = { 8c aa [2] a8 a4 [2] 83 88 [2] ad aa [2] b9 b1 [2] b6 ab [2] a8 b6 [2] aa b7 [2] b1 b1 [2] ad b6 [2] b1 99 }

  condition:
    any of them
}