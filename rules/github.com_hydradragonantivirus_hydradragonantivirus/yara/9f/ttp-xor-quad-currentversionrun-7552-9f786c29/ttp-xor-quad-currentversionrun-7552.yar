rule TTP_XOR_QUAD_CurrentVersionRun_7552 {
  strings:
    $key_7552 = { 26 3d [2] 02 33 [2] 29 1f [2] 07 3d [2] 13 26 [2] 1c 3c [2] 02 21 [2] 00 20 [2] 1b 26 [2] 07 21 [2] 1b 0e }

  condition:
    any of them
}