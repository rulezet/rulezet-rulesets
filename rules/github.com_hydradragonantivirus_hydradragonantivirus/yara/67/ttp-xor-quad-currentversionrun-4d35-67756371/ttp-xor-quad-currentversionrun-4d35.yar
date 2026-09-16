rule TTP_XOR_QUAD_CurrentVersionRun_4d35 {
  strings:
    $key_4d35 = { 1e 5a [2] 3a 54 [2] 11 78 [2] 3f 5a [2] 2b 41 [2] 24 5b [2] 3a 46 [2] 38 47 [2] 23 41 [2] 3f 46 [2] 23 69 }

  condition:
    any of them
}