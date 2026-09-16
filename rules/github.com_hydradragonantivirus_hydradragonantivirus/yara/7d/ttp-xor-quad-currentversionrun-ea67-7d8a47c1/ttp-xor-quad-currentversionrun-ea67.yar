rule TTP_XOR_QUAD_CurrentVersionRun_ea67 {
  strings:
    $key_ea67 = { b9 08 [2] 9d 06 [2] b6 2a [2] 98 08 [2] 8c 13 [2] 83 09 [2] 9d 14 [2] 9f 15 [2] 84 13 [2] 98 14 [2] 84 3b }

  condition:
    any of them
}