rule TTP_XOR_QUAD_CurrentVersionRun_ea48 {
  strings:
    $key_ea48 = { b9 27 [2] 9d 29 [2] b6 05 [2] 98 27 [2] 8c 3c [2] 83 26 [2] 9d 3b [2] 9f 3a [2] 84 3c [2] 98 3b [2] 84 14 }

  condition:
    any of them
}