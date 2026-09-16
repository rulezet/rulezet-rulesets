rule TTP_XOR_QUAD_CurrentVersionRun_7a5b {
  strings:
    $key_7a5b = { 29 34 [2] 0d 3a [2] 26 16 [2] 08 34 [2] 1c 2f [2] 13 35 [2] 0d 28 [2] 0f 29 [2] 14 2f [2] 08 28 [2] 14 07 }

  condition:
    any of them
}