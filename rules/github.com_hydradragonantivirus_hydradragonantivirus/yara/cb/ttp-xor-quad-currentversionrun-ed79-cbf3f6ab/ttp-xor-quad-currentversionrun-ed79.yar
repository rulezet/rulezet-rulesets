rule TTP_XOR_QUAD_CurrentVersionRun_ed79 {
  strings:
    $key_ed79 = { be 16 [2] 9a 18 [2] b1 34 [2] 9f 16 [2] 8b 0d [2] 84 17 [2] 9a 0a [2] 98 0b [2] 83 0d [2] 9f 0a [2] 83 25 }

  condition:
    any of them
}