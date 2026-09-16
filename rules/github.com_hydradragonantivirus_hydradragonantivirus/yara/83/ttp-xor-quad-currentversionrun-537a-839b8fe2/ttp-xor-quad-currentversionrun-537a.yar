rule TTP_XOR_QUAD_CurrentVersionRun_537a {
  strings:
    $key_537a = { 00 15 [2] 24 1b [2] 0f 37 [2] 21 15 [2] 35 0e [2] 3a 14 [2] 24 09 [2] 26 08 [2] 3d 0e [2] 21 09 [2] 3d 26 }

  condition:
    any of them
}