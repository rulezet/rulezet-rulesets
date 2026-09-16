rule TTP_XOR_QUAD_CurrentVersionRun_565b {
  strings:
    $key_565b = { 05 34 [2] 21 3a [2] 0a 16 [2] 24 34 [2] 30 2f [2] 3f 35 [2] 21 28 [2] 23 29 [2] 38 2f [2] 24 28 [2] 38 07 }

  condition:
    any of them
}