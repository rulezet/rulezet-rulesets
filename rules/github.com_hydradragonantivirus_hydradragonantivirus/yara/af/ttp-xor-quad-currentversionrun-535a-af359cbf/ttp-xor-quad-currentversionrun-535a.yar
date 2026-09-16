rule TTP_XOR_QUAD_CurrentVersionRun_535a {
  strings:
    $key_535a = { 00 35 [2] 24 3b [2] 0f 17 [2] 21 35 [2] 35 2e [2] 3a 34 [2] 24 29 [2] 26 28 [2] 3d 2e [2] 21 29 [2] 3d 06 }

  condition:
    any of them
}