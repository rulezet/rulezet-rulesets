rule TTP_XOR_QUAD_CurrentVersionRun_ed17 {
  strings:
    $key_ed17 = { be 78 [2] 9a 76 [2] b1 5a [2] 9f 78 [2] 8b 63 [2] 84 79 [2] 9a 64 [2] 98 65 [2] 83 63 [2] 9f 64 [2] 83 4b }

  condition:
    any of them
}