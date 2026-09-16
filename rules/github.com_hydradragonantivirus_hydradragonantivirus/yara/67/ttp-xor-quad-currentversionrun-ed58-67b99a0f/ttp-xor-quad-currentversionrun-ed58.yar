rule TTP_XOR_QUAD_CurrentVersionRun_ed58 {
  strings:
    $key_ed58 = { be 37 [2] 9a 39 [2] b1 15 [2] 9f 37 [2] 8b 2c [2] 84 36 [2] 9a 2b [2] 98 2a [2] 83 2c [2] 9f 2b [2] 83 04 }

  condition:
    any of them
}