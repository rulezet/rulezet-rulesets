rule TTP_XOR_QUAD_CurrentVersionRun_f452 {
  strings:
    $key_f452 = { a7 3d [2] 83 33 [2] a8 1f [2] 86 3d [2] 92 26 [2] 9d 3c [2] 83 21 [2] 81 20 [2] 9a 26 [2] 86 21 [2] 9a 0e }

  condition:
    any of them
}