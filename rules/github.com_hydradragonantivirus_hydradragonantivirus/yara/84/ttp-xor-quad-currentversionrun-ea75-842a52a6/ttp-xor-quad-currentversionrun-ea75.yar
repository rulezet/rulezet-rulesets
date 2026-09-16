rule TTP_XOR_QUAD_CurrentVersionRun_ea75 {
  strings:
    $key_ea75 = { b9 1a [2] 9d 14 [2] b6 38 [2] 98 1a [2] 8c 01 [2] 83 1b [2] 9d 06 [2] 9f 07 [2] 84 01 [2] 98 06 [2] 84 29 }

  condition:
    any of them
}