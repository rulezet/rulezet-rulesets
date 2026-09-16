rule TTP_XOR_QUAD_CurrentVersionRun_4f1b {
  strings:
    $key_4f1b = { 1c 74 [2] 38 7a [2] 13 56 [2] 3d 74 [2] 29 6f [2] 26 75 [2] 38 68 [2] 3a 69 [2] 21 6f [2] 3d 68 [2] 21 47 }

  condition:
    any of them
}