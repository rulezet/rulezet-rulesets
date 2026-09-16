rule TTP_XOR_QUAD_CurrentVersionRun_ed59 {
  strings:
    $key_ed59 = { be 36 [2] 9a 38 [2] b1 14 [2] 9f 36 [2] 8b 2d [2] 84 37 [2] 9a 2a [2] 98 2b [2] 83 2d [2] 9f 2a [2] 83 05 }

  condition:
    any of them
}