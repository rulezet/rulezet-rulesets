rule TTP_XOR_QUAD_CurrentVersionRun_ed0b {
  strings:
    $key_ed0b = { be 64 [2] 9a 6a [2] b1 46 [2] 9f 64 [2] 8b 7f [2] 84 65 [2] 9a 78 [2] 98 79 [2] 83 7f [2] 9f 78 [2] 83 57 }

  condition:
    any of them
}