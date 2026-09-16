rule TTP_XOR_QUAD_CurrentVersionRun_f44e {
  strings:
    $key_f44e = { a7 21 [2] 83 2f [2] a8 03 [2] 86 21 [2] 92 3a [2] 9d 20 [2] 83 3d [2] 81 3c [2] 9a 3a [2] 86 3d [2] 9a 12 }

  condition:
    any of them
}