rule TTP_XOR_QUAD_CurrentVersionRun_4f27 {
  strings:
    $key_4f27 = { 1c 48 [2] 38 46 [2] 13 6a [2] 3d 48 [2] 29 53 [2] 26 49 [2] 38 54 [2] 3a 55 [2] 21 53 [2] 3d 54 [2] 21 7b }

  condition:
    any of them
}