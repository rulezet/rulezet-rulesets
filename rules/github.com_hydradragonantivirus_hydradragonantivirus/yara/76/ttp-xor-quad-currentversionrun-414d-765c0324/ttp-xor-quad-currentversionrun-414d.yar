rule TTP_XOR_QUAD_CurrentVersionRun_414d {
  strings:
    $key_414d = { 12 22 [2] 36 2c [2] 1d 00 [2] 33 22 [2] 27 39 [2] 28 23 [2] 36 3e [2] 34 3f [2] 2f 39 [2] 33 3e [2] 2f 11 }

  condition:
    any of them
}