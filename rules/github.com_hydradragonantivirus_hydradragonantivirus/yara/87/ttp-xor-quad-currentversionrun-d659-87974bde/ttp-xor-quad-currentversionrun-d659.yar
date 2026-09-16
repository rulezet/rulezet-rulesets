rule TTP_XOR_QUAD_CurrentVersionRun_d659 {
  strings:
    $key_d659 = { 85 36 [2] a1 38 [2] 8a 14 [2] a4 36 [2] b0 2d [2] bf 37 [2] a1 2a [2] a3 2b [2] b8 2d [2] a4 2a [2] b8 05 }

  condition:
    any of them
}