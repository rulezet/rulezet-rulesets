rule TTP_XOR_QUAD_CurrentVersionRun_2045 {
  strings:
    $key_2045 = { 73 2a [2] 57 24 [2] 7c 08 [2] 52 2a [2] 46 31 [2] 49 2b [2] 57 36 [2] 55 37 [2] 4e 31 [2] 52 36 [2] 4e 19 }

  condition:
    any of them
}