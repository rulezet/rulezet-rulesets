rule TTP_XOR_QUAD_CurrentVersionRun_4d09 {
  strings:
    $key_4d09 = { 1e 66 [2] 3a 68 [2] 11 44 [2] 3f 66 [2] 2b 7d [2] 24 67 [2] 3a 7a [2] 38 7b [2] 23 7d [2] 3f 7a [2] 23 55 }

  condition:
    any of them
}