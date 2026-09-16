rule TTP_XOR_QUAD_CurrentVersionRun_6452 {
  strings:
    $key_6452 = { 37 3d [2] 13 33 [2] 38 1f [2] 16 3d [2] 02 26 [2] 0d 3c [2] 13 21 [2] 11 20 [2] 0a 26 [2] 16 21 [2] 0a 0e }

  condition:
    any of them
}