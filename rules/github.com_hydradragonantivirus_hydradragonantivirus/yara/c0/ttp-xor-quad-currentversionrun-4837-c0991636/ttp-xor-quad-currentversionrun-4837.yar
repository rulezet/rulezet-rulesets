rule TTP_XOR_QUAD_CurrentVersionRun_4837 {
  strings:
    $key_4837 = { 1b 58 [2] 3f 56 [2] 14 7a [2] 3a 58 [2] 2e 43 [2] 21 59 [2] 3f 44 [2] 3d 45 [2] 26 43 [2] 3a 44 [2] 26 6b }

  condition:
    any of them
}