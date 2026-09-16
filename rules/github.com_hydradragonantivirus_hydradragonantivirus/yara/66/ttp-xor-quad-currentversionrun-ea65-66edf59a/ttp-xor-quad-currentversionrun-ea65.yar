rule TTP_XOR_QUAD_CurrentVersionRun_ea65 {
  strings:
    $key_ea65 = { b9 0a [2] 9d 04 [2] b6 28 [2] 98 0a [2] 8c 11 [2] 83 0b [2] 9d 16 [2] 9f 17 [2] 84 11 [2] 98 16 [2] 84 39 }

  condition:
    any of them
}