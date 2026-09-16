rule TTP_XOR_QUAD_CurrentVersionRun_dbd8 {
  strings:
    $key_dbd8 = { 88 b7 [2] ac b9 [2] 87 95 [2] a9 b7 [2] bd ac [2] b2 b6 [2] ac ab [2] ae aa [2] b5 ac [2] a9 ab [2] b5 84 }

  condition:
    any of them
}