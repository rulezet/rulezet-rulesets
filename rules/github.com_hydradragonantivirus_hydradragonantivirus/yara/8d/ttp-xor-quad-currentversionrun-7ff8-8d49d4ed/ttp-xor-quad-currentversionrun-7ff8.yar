rule TTP_XOR_QUAD_CurrentVersionRun_7ff8 {
  strings:
    $key_7ff8 = { 2c 97 [2] 08 99 [2] 23 b5 [2] 0d 97 [2] 19 8c [2] 16 96 [2] 08 8b [2] 0a 8a [2] 11 8c [2] 0d 8b [2] 11 a4 }

  condition:
    any of them
}