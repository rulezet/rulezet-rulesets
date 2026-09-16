rule TTP_XOR_QUAD_CurrentVersionRun_2549 {
  strings:
    $key_2549 = { 76 26 [2] 52 28 [2] 79 04 [2] 57 26 [2] 43 3d [2] 4c 27 [2] 52 3a [2] 50 3b [2] 4b 3d [2] 57 3a [2] 4b 15 }

  condition:
    any of them
}