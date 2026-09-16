rule TTP_XOR_QUAD_CurrentVersionRun_274e {
  strings:
    $key_274e = { 74 21 [2] 50 2f [2] 7b 03 [2] 55 21 [2] 41 3a [2] 4e 20 [2] 50 3d [2] 52 3c [2] 49 3a [2] 55 3d [2] 49 12 }

  condition:
    any of them
}