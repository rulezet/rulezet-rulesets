rule TTP_XOR_QUAD_CurrentVersionRun_4f54 {
  strings:
    $key_4f54 = { 1c 3b [2] 38 35 [2] 13 19 [2] 3d 3b [2] 29 20 [2] 26 3a [2] 38 27 [2] 3a 26 [2] 21 20 [2] 3d 27 [2] 21 08 }

  condition:
    any of them
}