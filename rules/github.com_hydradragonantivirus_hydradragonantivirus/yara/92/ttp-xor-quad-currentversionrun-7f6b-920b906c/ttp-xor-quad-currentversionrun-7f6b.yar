rule TTP_XOR_QUAD_CurrentVersionRun_7f6b {
  strings:
    $key_7f6b = { 2c 04 [2] 08 0a [2] 23 26 [2] 0d 04 [2] 19 1f [2] 16 05 [2] 08 18 [2] 0a 19 [2] 11 1f [2] 0d 18 [2] 11 37 }

  condition:
    any of them
}