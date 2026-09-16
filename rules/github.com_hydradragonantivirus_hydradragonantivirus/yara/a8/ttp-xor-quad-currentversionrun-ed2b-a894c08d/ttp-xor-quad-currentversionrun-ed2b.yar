rule TTP_XOR_QUAD_CurrentVersionRun_ed2b {
  strings:
    $key_ed2b = { be 44 [2] 9a 4a [2] b1 66 [2] 9f 44 [2] 8b 5f [2] 84 45 [2] 9a 58 [2] 98 59 [2] 83 5f [2] 9f 58 [2] 83 77 }

  condition:
    any of them
}