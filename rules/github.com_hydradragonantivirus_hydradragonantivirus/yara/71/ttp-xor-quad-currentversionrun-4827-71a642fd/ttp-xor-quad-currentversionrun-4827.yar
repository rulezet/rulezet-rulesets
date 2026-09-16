rule TTP_XOR_QUAD_CurrentVersionRun_4827 {
  strings:
    $key_4827 = { 1b 48 [2] 3f 46 [2] 14 6a [2] 3a 48 [2] 2e 53 [2] 21 49 [2] 3f 54 [2] 3d 55 [2] 26 53 [2] 3a 54 [2] 26 7b }

  condition:
    any of them
}