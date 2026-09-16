rule TTP_XOR_QUAD_CurrentVersionRun_ea34 {
  strings:
    $key_ea34 = { b9 5b [2] 9d 55 [2] b6 79 [2] 98 5b [2] 8c 40 [2] 83 5a [2] 9d 47 [2] 9f 46 [2] 84 40 [2] 98 47 [2] 84 68 }

  condition:
    any of them
}