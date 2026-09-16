rule TTP_XOR_QUAD_CurrentVersionRun_434c {
  strings:
    $key_434c = { 10 23 [2] 34 2d [2] 1f 01 [2] 31 23 [2] 25 38 [2] 2a 22 [2] 34 3f [2] 36 3e [2] 2d 38 [2] 31 3f [2] 2d 10 }

  condition:
    any of them
}