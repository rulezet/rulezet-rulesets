rule TTP_XOR_QUAD_CurrentVersionRun_ed55 {
  strings:
    $key_ed55 = { be 3a [2] 9a 34 [2] b1 18 [2] 9f 3a [2] 8b 21 [2] 84 3b [2] 9a 26 [2] 98 27 [2] 83 21 [2] 9f 26 [2] 83 09 }

  condition:
    any of them
}