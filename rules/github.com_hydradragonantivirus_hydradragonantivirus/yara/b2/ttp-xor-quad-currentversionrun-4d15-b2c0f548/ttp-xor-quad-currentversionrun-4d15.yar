rule TTP_XOR_QUAD_CurrentVersionRun_4d15 {
  strings:
    $key_4d15 = { 1e 7a [2] 3a 74 [2] 11 58 [2] 3f 7a [2] 2b 61 [2] 24 7b [2] 3a 66 [2] 38 67 [2] 23 61 [2] 3f 66 [2] 23 49 }

  condition:
    any of them
}