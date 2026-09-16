rule TTP_XOR_QUAD_CurrentVersionRun_711e {
  strings:
    $key_711e = { 22 71 [2] 06 7f [2] 2d 53 [2] 03 71 [2] 17 6a [2] 18 70 [2] 06 6d [2] 04 6c [2] 1f 6a [2] 03 6d [2] 1f 42 }

  condition:
    any of them
}