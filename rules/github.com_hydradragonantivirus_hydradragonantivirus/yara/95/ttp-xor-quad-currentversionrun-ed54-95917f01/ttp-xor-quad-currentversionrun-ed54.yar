rule TTP_XOR_QUAD_CurrentVersionRun_ed54 {
  strings:
    $key_ed54 = { be 3b [2] 9a 35 [2] b1 19 [2] 9f 3b [2] 8b 20 [2] 84 3a [2] 9a 27 [2] 98 26 [2] 83 20 [2] 9f 27 [2] 83 08 }

  condition:
    any of them
}