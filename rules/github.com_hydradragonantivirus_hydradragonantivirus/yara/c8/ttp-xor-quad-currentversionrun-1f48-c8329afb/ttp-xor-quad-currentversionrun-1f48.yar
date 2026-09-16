rule TTP_XOR_QUAD_CurrentVersionRun_1f48 {
  strings:
    $key_1f48 = { 4c 27 [2] 68 29 [2] 43 05 [2] 6d 27 [2] 79 3c [2] 76 26 [2] 68 3b [2] 6a 3a [2] 71 3c [2] 6d 3b [2] 71 14 }

  condition:
    any of them
}