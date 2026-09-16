rule TTP_XOR_QUAD_CurrentVersionRun_604e {
  strings:
    $key_604e = { 33 21 [2] 17 2f [2] 3c 03 [2] 12 21 [2] 06 3a [2] 09 20 [2] 17 3d [2] 15 3c [2] 0e 3a [2] 12 3d [2] 0e 12 }

  condition:
    any of them
}