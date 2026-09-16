rule TTP_XOR_QUAD_CurrentVersionRun_1f09 {
  strings:
    $key_1f09 = { 4c 66 [2] 68 68 [2] 43 44 [2] 6d 66 [2] 79 7d [2] 76 67 [2] 68 7a [2] 6a 7b [2] 71 7d [2] 6d 7a [2] 71 55 }

  condition:
    any of them
}