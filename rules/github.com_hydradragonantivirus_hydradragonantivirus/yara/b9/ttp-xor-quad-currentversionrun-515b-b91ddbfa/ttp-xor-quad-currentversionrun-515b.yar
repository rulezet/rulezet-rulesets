rule TTP_XOR_QUAD_CurrentVersionRun_515b {
  strings:
    $key_515b = { 02 34 [2] 26 3a [2] 0d 16 [2] 23 34 [2] 37 2f [2] 38 35 [2] 26 28 [2] 24 29 [2] 3f 2f [2] 23 28 [2] 3f 07 }

  condition:
    any of them
}