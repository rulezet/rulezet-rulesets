rule TTP_XOR_QUAD_CurrentVersionRun_3847 {
  strings:
    $key_3847 = { 6b 28 [2] 4f 26 [2] 64 0a [2] 4a 28 [2] 5e 33 [2] 51 29 [2] 4f 34 [2] 4d 35 [2] 56 33 [2] 4a 34 [2] 56 1b }

  condition:
    any of them
}