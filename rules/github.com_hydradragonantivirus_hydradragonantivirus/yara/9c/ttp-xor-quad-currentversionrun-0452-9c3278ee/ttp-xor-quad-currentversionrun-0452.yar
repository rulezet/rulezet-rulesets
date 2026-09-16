rule TTP_XOR_QUAD_CurrentVersionRun_0452 {
  strings:
    $key_0452 = { 57 3d [2] 73 33 [2] 58 1f [2] 76 3d [2] 62 26 [2] 6d 3c [2] 73 21 [2] 71 20 [2] 6a 26 [2] 76 21 [2] 6a 0e }

  condition:
    any of them
}