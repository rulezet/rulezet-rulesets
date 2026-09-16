rule TTP_XOR_QUAD_CurrentVersionRun_14d8 {
  strings:
    $key_14d8 = { 47 b7 [2] 63 b9 [2] 48 95 [2] 66 b7 [2] 72 ac [2] 7d b6 [2] 63 ab [2] 61 aa [2] 7a ac [2] 66 ab [2] 7a 84 }

  condition:
    any of them
}