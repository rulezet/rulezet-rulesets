rule TTP_XOR_QUAD_CurrentVersionRun_545b {
  strings:
    $key_545b = { 07 34 [2] 23 3a [2] 08 16 [2] 26 34 [2] 32 2f [2] 3d 35 [2] 23 28 [2] 21 29 [2] 3a 2f [2] 26 28 [2] 3a 07 }

  condition:
    any of them
}