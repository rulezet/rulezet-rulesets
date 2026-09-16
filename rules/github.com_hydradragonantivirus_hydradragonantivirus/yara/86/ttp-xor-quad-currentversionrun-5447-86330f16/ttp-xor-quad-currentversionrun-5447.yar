rule TTP_XOR_QUAD_CurrentVersionRun_5447 {
  strings:
    $key_5447 = { 07 28 [2] 23 26 [2] 08 0a [2] 26 28 [2] 32 33 [2] 3d 29 [2] 23 34 [2] 21 35 [2] 3a 33 [2] 26 34 [2] 3a 1b }

  condition:
    any of them
}