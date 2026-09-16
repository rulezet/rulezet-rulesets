rule TTP_XOR_QUAD_CurrentVersionRun_6507 {
  strings:
    $key_6507 = { 36 68 [2] 12 66 [2] 39 4a [2] 17 68 [2] 03 73 [2] 0c 69 [2] 12 74 [2] 10 75 [2] 0b 73 [2] 17 74 [2] 0b 5b }

  condition:
    any of them
}