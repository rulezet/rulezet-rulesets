rule TTP_XOR_QUAD_CurrentVersionRun_7a59 {
  strings:
    $key_7a59 = { 29 36 [2] 0d 38 [2] 26 14 [2] 08 36 [2] 1c 2d [2] 13 37 [2] 0d 2a [2] 0f 2b [2] 14 2d [2] 08 2a [2] 14 05 }

  condition:
    any of them
}