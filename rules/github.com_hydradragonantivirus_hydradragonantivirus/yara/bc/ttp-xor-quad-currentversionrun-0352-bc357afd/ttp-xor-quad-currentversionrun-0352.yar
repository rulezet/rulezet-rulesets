rule TTP_XOR_QUAD_CurrentVersionRun_0352 {
  strings:
    $key_0352 = { 50 3d [2] 74 33 [2] 5f 1f [2] 71 3d [2] 65 26 [2] 6a 3c [2] 74 21 [2] 76 20 [2] 6d 26 [2] 71 21 [2] 6d 0e }

  condition:
    any of them
}