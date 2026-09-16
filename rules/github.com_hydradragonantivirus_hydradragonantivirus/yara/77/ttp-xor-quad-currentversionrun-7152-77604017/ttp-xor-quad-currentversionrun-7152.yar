rule TTP_XOR_QUAD_CurrentVersionRun_7152 {
  strings:
    $key_7152 = { 22 3d [2] 06 33 [2] 2d 1f [2] 03 3d [2] 17 26 [2] 18 3c [2] 06 21 [2] 04 20 [2] 1f 26 [2] 03 21 [2] 1f 0e }

  condition:
    any of them
}