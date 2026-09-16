rule TTP_XOR_QUAD_CurrentVersionRun_414c {
  strings:
    $key_414c = { 12 23 [2] 36 2d [2] 1d 01 [2] 33 23 [2] 27 38 [2] 28 22 [2] 36 3f [2] 34 3e [2] 2f 38 [2] 33 3f [2] 2f 10 }

  condition:
    any of them
}