rule TTP_XOR_QUAD_CurrentVersionRun_4d34 {
  strings:
    $key_4d34 = { 1e 5b [2] 3a 55 [2] 11 79 [2] 3f 5b [2] 2b 40 [2] 24 5a [2] 3a 47 [2] 38 46 [2] 23 40 [2] 3f 47 [2] 23 68 }

  condition:
    any of them
}