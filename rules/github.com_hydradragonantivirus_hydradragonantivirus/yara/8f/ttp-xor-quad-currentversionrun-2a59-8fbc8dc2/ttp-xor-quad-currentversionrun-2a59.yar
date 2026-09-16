rule TTP_XOR_QUAD_CurrentVersionRun_2a59 {
  strings:
    $key_2a59 = { 79 36 [2] 5d 38 [2] 76 14 [2] 58 36 [2] 4c 2d [2] 43 37 [2] 5d 2a [2] 5f 2b [2] 44 2d [2] 58 2a [2] 44 05 }

  condition:
    any of them
}