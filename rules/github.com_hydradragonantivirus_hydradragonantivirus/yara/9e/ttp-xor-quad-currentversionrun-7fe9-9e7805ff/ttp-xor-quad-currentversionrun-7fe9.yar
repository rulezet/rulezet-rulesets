rule TTP_XOR_QUAD_CurrentVersionRun_7fe9 {
  strings:
    $key_7fe9 = { 2c 86 [2] 08 88 [2] 23 a4 [2] 0d 86 [2] 19 9d [2] 16 87 [2] 08 9a [2] 0a 9b [2] 11 9d [2] 0d 9a [2] 11 b5 }

  condition:
    any of them
}