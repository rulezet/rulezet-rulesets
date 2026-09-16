rule TTP_XOR_QUAD_CurrentVersionRun_ed19 {
  strings:
    $key_ed19 = { be 76 [2] 9a 78 [2] b1 54 [2] 9f 76 [2] 8b 6d [2] 84 77 [2] 9a 6a [2] 98 6b [2] 83 6d [2] 9f 6a [2] 83 45 }

  condition:
    any of them
}