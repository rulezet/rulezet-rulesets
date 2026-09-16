rule TTP_XOR_QUAD_CurrentVersionRun_1748 {
  strings:
    $key_1748 = { 44 27 [2] 60 29 [2] 4b 05 [2] 65 27 [2] 71 3c [2] 7e 26 [2] 60 3b [2] 62 3a [2] 79 3c [2] 65 3b [2] 79 14 }

  condition:
    any of them
}