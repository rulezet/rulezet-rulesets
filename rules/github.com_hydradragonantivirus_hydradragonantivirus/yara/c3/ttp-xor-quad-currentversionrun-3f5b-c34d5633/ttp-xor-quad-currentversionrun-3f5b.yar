rule TTP_XOR_QUAD_CurrentVersionRun_3f5b {
  strings:
    $key_3f5b = { 6c 34 [2] 48 3a [2] 63 16 [2] 4d 34 [2] 59 2f [2] 56 35 [2] 48 28 [2] 4a 29 [2] 51 2f [2] 4d 28 [2] 51 07 }

  condition:
    any of them
}