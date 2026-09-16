rule TTP_XOR_QUAD_CurrentVersionRun_1f69 {
  strings:
    $key_1f69 = { 4c 06 [2] 68 08 [2] 43 24 [2] 6d 06 [2] 79 1d [2] 76 07 [2] 68 1a [2] 6a 1b [2] 71 1d [2] 6d 1a [2] 71 35 }

  condition:
    any of them
}