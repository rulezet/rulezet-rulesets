rule TTP_XOR_QUAD_CurrentVersionRun_7ff9 {
  strings:
    $key_7ff9 = { 2c 96 [2] 08 98 [2] 23 b4 [2] 0d 96 [2] 19 8d [2] 16 97 [2] 08 8a [2] 0a 8b [2] 11 8d [2] 0d 8a [2] 11 a5 }

  condition:
    any of them
}