rule TTP_XOR_QUAD_CurrentVersionRun_7635 {
  strings:
    $key_7635 = { 25 5a [2] 01 54 [2] 2a 78 [2] 04 5a [2] 10 41 [2] 1f 5b [2] 01 46 [2] 03 47 [2] 18 41 [2] 04 46 [2] 18 69 }

  condition:
    any of them
}