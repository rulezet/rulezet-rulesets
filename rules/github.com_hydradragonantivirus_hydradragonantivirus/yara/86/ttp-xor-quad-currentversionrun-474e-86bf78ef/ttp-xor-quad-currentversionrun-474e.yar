rule TTP_XOR_QUAD_CurrentVersionRun_474e {
  strings:
    $key_474e = { 14 21 [2] 30 2f [2] 1b 03 [2] 35 21 [2] 21 3a [2] 2e 20 [2] 30 3d [2] 32 3c [2] 29 3a [2] 35 3d [2] 29 12 }

  condition:
    any of them
}