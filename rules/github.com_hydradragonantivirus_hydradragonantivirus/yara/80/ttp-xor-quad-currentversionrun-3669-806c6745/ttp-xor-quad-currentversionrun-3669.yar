rule TTP_XOR_QUAD_CurrentVersionRun_3669 {
  strings:
    $key_3669 = { 65 06 [2] 41 08 [2] 6a 24 [2] 44 06 [2] 50 1d [2] 5f 07 [2] 41 1a [2] 43 1b [2] 58 1d [2] 44 1a [2] 58 35 }

  condition:
    any of them
}