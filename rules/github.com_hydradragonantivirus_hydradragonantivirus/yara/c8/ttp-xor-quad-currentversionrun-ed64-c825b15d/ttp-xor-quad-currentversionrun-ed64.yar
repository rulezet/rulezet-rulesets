rule TTP_XOR_QUAD_CurrentVersionRun_ed64 {
  strings:
    $key_ed64 = { be 0b [2] 9a 05 [2] b1 29 [2] 9f 0b [2] 8b 10 [2] 84 0a [2] 9a 17 [2] 98 16 [2] 83 10 [2] 9f 17 [2] 83 38 }

  condition:
    any of them
}