rule TTP_XOR_QUAD_CurrentVersionRun_535c {
  strings:
    $key_535c = { 00 33 [2] 24 3d [2] 0f 11 [2] 21 33 [2] 35 28 [2] 3a 32 [2] 24 2f [2] 26 2e [2] 3d 28 [2] 21 2f [2] 3d 00 }

  condition:
    any of them
}