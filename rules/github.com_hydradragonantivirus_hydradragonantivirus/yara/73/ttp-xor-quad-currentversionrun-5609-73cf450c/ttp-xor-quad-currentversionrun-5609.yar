rule TTP_XOR_QUAD_CurrentVersionRun_5609 {
  strings:
    $key_5609 = { 05 66 [2] 21 68 [2] 0a 44 [2] 24 66 [2] 30 7d [2] 3f 67 [2] 21 7a [2] 23 7b [2] 38 7d [2] 24 7a [2] 38 55 }

  condition:
    any of them
}