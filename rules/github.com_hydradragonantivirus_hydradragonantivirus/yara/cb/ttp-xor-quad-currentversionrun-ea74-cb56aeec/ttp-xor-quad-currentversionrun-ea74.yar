rule TTP_XOR_QUAD_CurrentVersionRun_ea74 {
  strings:
    $key_ea74 = { b9 1b [2] 9d 15 [2] b6 39 [2] 98 1b [2] 8c 00 [2] 83 1a [2] 9d 07 [2] 9f 06 [2] 84 00 [2] 98 07 [2] 84 28 }

  condition:
    any of them
}