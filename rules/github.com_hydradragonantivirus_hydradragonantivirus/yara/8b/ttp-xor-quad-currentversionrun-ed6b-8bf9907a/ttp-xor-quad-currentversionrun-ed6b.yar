rule TTP_XOR_QUAD_CurrentVersionRun_ed6b {
  strings:
    $key_ed6b = { be 04 [2] 9a 0a [2] b1 26 [2] 9f 04 [2] 8b 1f [2] 84 05 [2] 9a 18 [2] 98 19 [2] 83 1f [2] 9f 18 [2] 83 37 }

  condition:
    any of them
}