rule TTP_XOR_QUAD_CurrentVersionRun_7f07 {
  strings:
    $key_7f07 = { 2c 68 [2] 08 66 [2] 23 4a [2] 0d 68 [2] 19 73 [2] 16 69 [2] 08 74 [2] 0a 75 [2] 11 73 [2] 0d 74 [2] 11 5b }

  condition:
    any of them
}