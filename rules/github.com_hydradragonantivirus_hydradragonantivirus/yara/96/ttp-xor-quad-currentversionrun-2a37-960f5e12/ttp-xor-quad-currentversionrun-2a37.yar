rule TTP_XOR_QUAD_CurrentVersionRun_2a37 {
  strings:
    $key_2a37 = { 79 58 [2] 5d 56 [2] 76 7a [2] 58 58 [2] 4c 43 [2] 43 59 [2] 5d 44 [2] 5f 45 [2] 44 43 [2] 58 44 [2] 44 6b }

  condition:
    any of them
}