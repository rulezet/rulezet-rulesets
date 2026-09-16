rule TTP_XOR_QUAD_CurrentVersionRun_074e {
  strings:
    $key_074e = { 54 21 [2] 70 2f [2] 5b 03 [2] 75 21 [2] 61 3a [2] 6e 20 [2] 70 3d [2] 72 3c [2] 69 3a [2] 75 3d [2] 69 12 }

  condition:
    any of them
}