rule TTP_XOR_QUAD_CurrentVersionRun_ded8 {
  strings:
    $key_ded8 = { 8d b7 [2] a9 b9 [2] 82 95 [2] ac b7 [2] b8 ac [2] b7 b6 [2] a9 ab [2] ab aa [2] b0 ac [2] ac ab [2] b0 84 }

  condition:
    any of them
}