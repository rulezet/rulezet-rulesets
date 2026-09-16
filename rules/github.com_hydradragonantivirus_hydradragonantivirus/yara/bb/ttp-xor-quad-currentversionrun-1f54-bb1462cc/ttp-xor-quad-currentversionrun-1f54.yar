rule TTP_XOR_QUAD_CurrentVersionRun_1f54 {
  strings:
    $key_1f54 = { 4c 3b [2] 68 35 [2] 43 19 [2] 6d 3b [2] 79 20 [2] 76 3a [2] 68 27 [2] 6a 26 [2] 71 20 [2] 6d 27 [2] 71 08 }

  condition:
    any of them
}