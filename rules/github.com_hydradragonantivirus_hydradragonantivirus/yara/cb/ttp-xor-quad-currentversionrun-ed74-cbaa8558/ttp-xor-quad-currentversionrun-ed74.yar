rule TTP_XOR_QUAD_CurrentVersionRun_ed74 {
  strings:
    $key_ed74 = { be 1b [2] 9a 15 [2] b1 39 [2] 9f 1b [2] 8b 00 [2] 84 1a [2] 9a 07 [2] 98 06 [2] 83 00 [2] 9f 07 [2] 83 28 }

  condition:
    any of them
}