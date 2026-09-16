rule TTP_XOR_QUAD_CurrentVersionRun_53f2 {
  strings:
    $key_53f2 = { 00 9d [2] 24 93 [2] 0f bf [2] 21 9d [2] 35 86 [2] 3a 9c [2] 24 81 [2] 26 80 [2] 3d 86 [2] 21 81 [2] 3d ae }

  condition:
    any of them
}