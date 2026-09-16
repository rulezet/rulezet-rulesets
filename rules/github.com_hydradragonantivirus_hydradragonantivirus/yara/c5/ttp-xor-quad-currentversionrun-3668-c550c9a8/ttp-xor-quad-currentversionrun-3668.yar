rule TTP_XOR_QUAD_CurrentVersionRun_3668 {
  strings:
    $key_3668 = { 65 07 [2] 41 09 [2] 6a 25 [2] 44 07 [2] 50 1c [2] 5f 06 [2] 41 1b [2] 43 1a [2] 58 1c [2] 44 1b [2] 58 34 }

  condition:
    any of them
}