rule TTP_XOR_QUAD_CurrentVersionRun_536a {
  strings:
    $key_536a = { 00 05 [2] 24 0b [2] 0f 27 [2] 21 05 [2] 35 1e [2] 3a 04 [2] 24 19 [2] 26 18 [2] 3d 1e [2] 21 19 [2] 3d 36 }

  condition:
    any of them
}