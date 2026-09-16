rule TTP_XOR_QUAD_CurrentVersionRun_7f2b {
  strings:
    $key_7f2b = { 2c 44 [2] 08 4a [2] 23 66 [2] 0d 44 [2] 19 5f [2] 16 45 [2] 08 58 [2] 0a 59 [2] 11 5f [2] 0d 58 [2] 11 77 }

  condition:
    any of them
}