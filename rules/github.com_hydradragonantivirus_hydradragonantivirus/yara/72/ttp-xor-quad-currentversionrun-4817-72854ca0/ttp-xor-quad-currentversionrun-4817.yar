rule TTP_XOR_QUAD_CurrentVersionRun_4817 {
  strings:
    $key_4817 = { 1b 78 [2] 3f 76 [2] 14 5a [2] 3a 78 [2] 2e 63 [2] 21 79 [2] 3f 64 [2] 3d 65 [2] 26 63 [2] 3a 64 [2] 26 4b }

  condition:
    any of them
}