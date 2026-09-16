rule TTP_XOR_QUAD_CurrentVersionRun_d648 {
  strings:
    $key_d648 = { 85 27 [2] a1 29 [2] 8a 05 [2] a4 27 [2] b0 3c [2] bf 26 [2] a1 3b [2] a3 3a [2] b8 3c [2] a4 3b [2] b8 14 }

  condition:
    any of them
}