rule TTP_XOR_QUAD_CurrentVersionRun_7fe4 {
  strings:
    $key_7fe4 = { 2c 8b [2] 08 85 [2] 23 a9 [2] 0d 8b [2] 19 90 [2] 16 8a [2] 08 97 [2] 0a 96 [2] 11 90 [2] 0d 97 [2] 11 b8 }

  condition:
    any of them
}