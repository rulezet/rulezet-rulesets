rule TTP_XOR_QUAD_CurrentVersionRun_5327 {
  strings:
    $key_5327 = { 00 48 [2] 24 46 [2] 0f 6a [2] 21 48 [2] 35 53 [2] 3a 49 [2] 24 54 [2] 26 55 [2] 3d 53 [2] 21 54 [2] 3d 7b }

  condition:
    any of them
}