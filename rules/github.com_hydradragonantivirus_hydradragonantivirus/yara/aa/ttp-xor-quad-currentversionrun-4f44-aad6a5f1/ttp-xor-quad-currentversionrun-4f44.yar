rule TTP_XOR_QUAD_CurrentVersionRun_4f44 {
  strings:
    $key_4f44 = { 1c 2b [2] 38 25 [2] 13 09 [2] 3d 2b [2] 29 30 [2] 26 2a [2] 38 37 [2] 3a 36 [2] 21 30 [2] 3d 37 [2] 21 18 }

  condition:
    any of them
}