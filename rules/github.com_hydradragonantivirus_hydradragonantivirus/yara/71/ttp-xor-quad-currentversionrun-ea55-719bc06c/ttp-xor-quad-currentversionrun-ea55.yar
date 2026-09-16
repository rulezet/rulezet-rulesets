rule TTP_XOR_QUAD_CurrentVersionRun_ea55 {
  strings:
    $key_ea55 = { b9 3a [2] 9d 34 [2] b6 18 [2] 98 3a [2] 8c 21 [2] 83 3b [2] 9d 26 [2] 9f 27 [2] 84 21 [2] 98 26 [2] 84 09 }

  condition:
    any of them
}