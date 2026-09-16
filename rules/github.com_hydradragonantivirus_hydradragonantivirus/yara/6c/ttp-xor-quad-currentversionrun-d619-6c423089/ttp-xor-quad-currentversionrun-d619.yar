rule TTP_XOR_QUAD_CurrentVersionRun_d619 {
  strings:
    $key_d619 = { 85 76 [2] a1 78 [2] 8a 54 [2] a4 76 [2] b0 6d [2] bf 77 [2] a1 6a [2] a3 6b [2] b8 6d [2] a4 6a [2] b8 45 }

  condition:
    any of them
}