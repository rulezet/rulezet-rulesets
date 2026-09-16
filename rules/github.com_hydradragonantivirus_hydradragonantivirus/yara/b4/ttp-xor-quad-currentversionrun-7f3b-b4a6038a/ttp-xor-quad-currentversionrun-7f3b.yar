rule TTP_XOR_QUAD_CurrentVersionRun_7f3b {
  strings:
    $key_7f3b = { 2c 54 [2] 08 5a [2] 23 76 [2] 0d 54 [2] 19 4f [2] 16 55 [2] 08 48 [2] 0a 49 [2] 11 4f [2] 0d 48 [2] 11 67 }

  condition:
    any of them
}