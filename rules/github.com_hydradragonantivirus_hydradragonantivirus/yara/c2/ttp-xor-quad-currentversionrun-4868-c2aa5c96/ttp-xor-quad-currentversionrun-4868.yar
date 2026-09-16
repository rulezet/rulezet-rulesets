rule TTP_XOR_QUAD_CurrentVersionRun_4868 {
  strings:
    $key_4868 = { 1b 07 [2] 3f 09 [2] 14 25 [2] 3a 07 [2] 2e 1c [2] 21 06 [2] 3f 1b [2] 3d 1a [2] 26 1c [2] 3a 1b [2] 26 34 }

  condition:
    any of them
}