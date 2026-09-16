rule TTP_XOR_QUAD_CurrentVersionRun_ffd8 {
  strings:
    $key_ffd8 = { ac b7 [2] 88 b9 [2] a3 95 [2] 8d b7 [2] 99 ac [2] 96 b6 [2] 88 ab [2] 8a aa [2] 91 ac [2] 8d ab [2] 91 84 }

  condition:
    any of them
}