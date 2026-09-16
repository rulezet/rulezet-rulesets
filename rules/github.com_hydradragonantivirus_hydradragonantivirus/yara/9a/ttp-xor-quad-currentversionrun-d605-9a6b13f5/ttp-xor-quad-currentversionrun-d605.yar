rule TTP_XOR_QUAD_CurrentVersionRun_d605 {
  strings:
    $key_d605 = { 85 6a [2] a1 64 [2] 8a 48 [2] a4 6a [2] b0 71 [2] bf 6b [2] a1 76 [2] a3 77 [2] b8 71 [2] a4 76 [2] b8 59 }

  condition:
    any of them
}