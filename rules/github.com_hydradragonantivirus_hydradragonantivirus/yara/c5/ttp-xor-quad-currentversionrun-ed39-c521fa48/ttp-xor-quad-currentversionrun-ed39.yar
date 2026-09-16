rule TTP_XOR_QUAD_CurrentVersionRun_ed39 {
  strings:
    $key_ed39 = { be 56 [2] 9a 58 [2] b1 74 [2] 9f 56 [2] 8b 4d [2] 84 57 [2] 9a 4a [2] 98 4b [2] 83 4d [2] 9f 4a [2] 83 65 }

  condition:
    any of them
}