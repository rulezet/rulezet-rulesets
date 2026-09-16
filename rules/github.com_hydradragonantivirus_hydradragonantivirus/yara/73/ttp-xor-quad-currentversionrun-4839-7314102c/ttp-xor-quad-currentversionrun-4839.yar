rule TTP_XOR_QUAD_CurrentVersionRun_4839 {
  strings:
    $key_4839 = { 1b 56 [2] 3f 58 [2] 14 74 [2] 3a 56 [2] 2e 4d [2] 21 57 [2] 3f 4a [2] 3d 4b [2] 26 4d [2] 3a 4a [2] 26 65 }

  condition:
    any of them
}