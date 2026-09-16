rule TTP_XOR_QUAD_CurrentVersionRun_dfbf {
  strings:
    $key_dfbf = { 8c d0 [2] a8 de [2] 83 f2 [2] ad d0 [2] b9 cb [2] b6 d1 [2] a8 cc [2] aa cd [2] b1 cb [2] ad cc [2] b1 e3 }

  condition:
    any of them
}