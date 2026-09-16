rule TTP_XOR_QUAD_CurrentVersionRun_1352 {
  strings:
    $key_1352 = { 40 3d [2] 64 33 [2] 4f 1f [2] 61 3d [2] 75 26 [2] 7a 3c [2] 64 21 [2] 66 20 [2] 7d 26 [2] 61 21 [2] 7d 0e }

  condition:
    any of them
}