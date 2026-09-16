rule TTP_XOR_QUAD_CurrentVersionRun_414e {
  strings:
    $key_414e = { 12 21 [2] 36 2f [2] 1d 03 [2] 33 21 [2] 27 3a [2] 28 20 [2] 36 3d [2] 34 3c [2] 2f 3a [2] 33 3d [2] 2f 12 }

  condition:
    any of them
}