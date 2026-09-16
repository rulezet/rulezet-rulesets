rule TTP_XOR_QUAD_CurrentVersionRun_4352 {
  strings:
    $key_4352 = { 10 3d [2] 34 33 [2] 1f 1f [2] 31 3d [2] 25 26 [2] 2a 3c [2] 34 21 [2] 36 20 [2] 2d 26 [2] 31 21 [2] 2d 0e }

  condition:
    any of them
}