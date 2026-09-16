rule TTP_XOR_QUAD_CurrentVersionRun_ed77 {
  strings:
    $key_ed77 = { be 18 [2] 9a 16 [2] b1 3a [2] 9f 18 [2] 8b 03 [2] 84 19 [2] 9a 04 [2] 98 05 [2] 83 03 [2] 9f 04 [2] 83 2b }

  condition:
    any of them
}