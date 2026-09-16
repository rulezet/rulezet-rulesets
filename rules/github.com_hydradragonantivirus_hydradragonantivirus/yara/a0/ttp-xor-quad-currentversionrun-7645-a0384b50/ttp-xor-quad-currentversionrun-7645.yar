rule TTP_XOR_QUAD_CurrentVersionRun_7645 {
  strings:
    $key_7645 = { 25 2a [2] 01 24 [2] 2a 08 [2] 04 2a [2] 10 31 [2] 1f 2b [2] 01 36 [2] 03 37 [2] 18 31 [2] 04 36 [2] 18 19 }

  condition:
    any of them
}