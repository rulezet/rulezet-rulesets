rule TTP_XOR_QUAD_CurrentVersionRun_7b09 {
  strings:
    $key_7b09 = { 28 66 [2] 0c 68 [2] 27 44 [2] 09 66 [2] 1d 7d [2] 12 67 [2] 0c 7a [2] 0e 7b [2] 15 7d [2] 09 7a [2] 15 55 }

  condition:
    any of them
}