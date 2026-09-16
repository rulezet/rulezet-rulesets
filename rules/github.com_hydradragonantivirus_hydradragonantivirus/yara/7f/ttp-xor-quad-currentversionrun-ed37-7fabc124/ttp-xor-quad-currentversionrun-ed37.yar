rule TTP_XOR_QUAD_CurrentVersionRun_ed37 {
  strings:
    $key_ed37 = { be 58 [2] 9a 56 [2] b1 7a [2] 9f 58 [2] 8b 43 [2] 84 59 [2] 9a 44 [2] 98 45 [2] 83 43 [2] 9f 44 [2] 83 6b }

  condition:
    any of them
}