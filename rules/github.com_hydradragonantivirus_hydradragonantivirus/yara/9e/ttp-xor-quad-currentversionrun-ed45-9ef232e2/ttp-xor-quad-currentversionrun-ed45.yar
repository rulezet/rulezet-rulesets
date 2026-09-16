rule TTP_XOR_QUAD_CurrentVersionRun_ed45 {
  strings:
    $key_ed45 = { be 2a [2] 9a 24 [2] b1 08 [2] 9f 2a [2] 8b 31 [2] 84 2b [2] 9a 36 [2] 98 37 [2] 83 31 [2] 9f 36 [2] 83 19 }

  condition:
    any of them
}