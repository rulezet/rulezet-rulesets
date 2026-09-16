rule TTP_XOR_QUAD_CurrentVersionRun_ea56 {
  strings:
    $key_ea56 = { b9 39 [2] 9d 37 [2] b6 1b [2] 98 39 [2] 8c 22 [2] 83 38 [2] 9d 25 [2] 9f 24 [2] 84 22 [2] 98 25 [2] 84 0a }

  condition:
    any of them
}