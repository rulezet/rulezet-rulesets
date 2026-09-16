rule TTP_XOR_QUAD_CurrentVersionRun_3645 {
  strings:
    $key_3645 = { 65 2a [2] 41 24 [2] 6a 08 [2] 44 2a [2] 50 31 [2] 5f 2b [2] 41 36 [2] 43 37 [2] 58 31 [2] 44 36 [2] 58 19 }

  condition:
    any of them
}