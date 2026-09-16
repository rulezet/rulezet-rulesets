rule TTP_XOR_QUAD_CurrentVersionRun_ed1b {
  strings:
    $key_ed1b = { be 74 [2] 9a 7a [2] b1 56 [2] 9f 74 [2] 8b 6f [2] 84 75 [2] 9a 68 [2] 98 69 [2] 83 6f [2] 9f 68 [2] 83 47 }

  condition:
    any of them
}