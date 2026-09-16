rule TTP_XOR_QUAD_CurrentVersionRun_4f1a {
  strings:
    $key_4f1a = { 1c 75 [2] 38 7b [2] 13 57 [2] 3d 75 [2] 29 6e [2] 26 74 [2] 38 69 [2] 3a 68 [2] 21 6e [2] 3d 69 [2] 21 46 }

  condition:
    any of them
}