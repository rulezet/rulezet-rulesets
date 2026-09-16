rule TTP_XOR_QUAD_CurrentVersionRun_2a49 {
  strings:
    $key_2a49 = { 79 26 [2] 5d 28 [2] 76 04 [2] 58 26 [2] 4c 3d [2] 43 27 [2] 5d 3a [2] 5f 3b [2] 44 3d [2] 58 3a [2] 44 15 }

  condition:
    any of them
}