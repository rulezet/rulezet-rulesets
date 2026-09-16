rule TTP_XOR_QUAD_CurrentVersionRun_434d {
  strings:
    $key_434d = { 10 22 [2] 34 2c [2] 1f 00 [2] 31 22 [2] 25 39 [2] 2a 23 [2] 34 3e [2] 36 3f [2] 2d 39 [2] 31 3e [2] 2d 11 }

  condition:
    any of them
}