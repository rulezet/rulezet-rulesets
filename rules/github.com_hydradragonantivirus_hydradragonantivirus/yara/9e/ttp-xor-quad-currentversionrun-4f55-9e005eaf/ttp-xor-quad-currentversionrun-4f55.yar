rule TTP_XOR_QUAD_CurrentVersionRun_4f55 {
  strings:
    $key_4f55 = { 1c 3a [2] 38 34 [2] 13 18 [2] 3d 3a [2] 29 21 [2] 26 3b [2] 38 26 [2] 3a 27 [2] 21 21 [2] 3d 26 [2] 21 09 }

  condition:
    any of them
}