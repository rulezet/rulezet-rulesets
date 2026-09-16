rule TTP_XOR_QUAD_CurrentVersionRun_4f47 {
  strings:
    $key_4f47 = { 1c 28 [2] 38 26 [2] 13 0a [2] 3d 28 [2] 29 33 [2] 26 29 [2] 38 34 [2] 3a 35 [2] 21 33 [2] 3d 34 [2] 21 1b }

  condition:
    any of them
}