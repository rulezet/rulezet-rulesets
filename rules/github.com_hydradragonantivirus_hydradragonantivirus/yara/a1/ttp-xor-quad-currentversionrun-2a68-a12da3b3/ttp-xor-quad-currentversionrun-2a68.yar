rule TTP_XOR_QUAD_CurrentVersionRun_2a68 {
  strings:
    $key_2a68 = { 79 07 [2] 5d 09 [2] 76 25 [2] 58 07 [2] 4c 1c [2] 43 06 [2] 5d 1b [2] 5f 1a [2] 44 1c [2] 58 1b [2] 44 34 }

  condition:
    any of them
}