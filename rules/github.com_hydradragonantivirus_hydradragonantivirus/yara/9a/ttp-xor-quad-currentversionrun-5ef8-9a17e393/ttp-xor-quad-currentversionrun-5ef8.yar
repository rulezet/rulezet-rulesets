rule TTP_XOR_QUAD_CurrentVersionRun_5ef8 {
  strings:
    $key_5ef8 = { 0d 97 [2] 29 99 [2] 02 b5 [2] 2c 97 [2] 38 8c [2] 37 96 [2] 29 8b [2] 2b 8a [2] 30 8c [2] 2c 8b [2] 30 a4 }

  condition:
    any of them
}