rule TTP_XOR_QUAD_CurrentVersionRun_7f15 {
  strings:
    $key_7f15 = { 2c 7a [2] 08 74 [2] 23 58 [2] 0d 7a [2] 19 61 [2] 16 7b [2] 08 66 [2] 0a 67 [2] 11 61 [2] 0d 66 [2] 11 49 }

  condition:
    any of them
}