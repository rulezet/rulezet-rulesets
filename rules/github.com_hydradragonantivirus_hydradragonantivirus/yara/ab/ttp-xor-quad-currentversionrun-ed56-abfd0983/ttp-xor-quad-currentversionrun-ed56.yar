rule TTP_XOR_QUAD_CurrentVersionRun_ed56 {
  strings:
    $key_ed56 = { be 39 [2] 9a 37 [2] b1 1b [2] 9f 39 [2] 8b 22 [2] 84 38 [2] 9a 25 [2] 98 24 [2] 83 22 [2] 9f 25 [2] 83 0a }

  condition:
    any of them
}