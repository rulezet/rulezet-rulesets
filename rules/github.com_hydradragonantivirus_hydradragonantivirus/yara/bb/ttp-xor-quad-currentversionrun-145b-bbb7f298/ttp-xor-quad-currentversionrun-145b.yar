rule TTP_XOR_QUAD_CurrentVersionRun_145b {
  strings:
    $key_145b = { 47 34 [2] 63 3a [2] 48 16 [2] 66 34 [2] 72 2f [2] 7d 35 [2] 63 28 [2] 61 29 [2] 7a 2f [2] 66 28 [2] 7a 07 }

  condition:
    any of them
}