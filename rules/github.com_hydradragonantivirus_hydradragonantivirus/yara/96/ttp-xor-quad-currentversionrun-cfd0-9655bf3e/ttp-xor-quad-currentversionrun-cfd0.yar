rule TTP_XOR_QUAD_CurrentVersionRun_cfd0 {
  strings:
    $key_cfd0 = { 9c bf [2] b8 b1 [2] 93 9d [2] bd bf [2] a9 a4 [2] a6 be [2] b8 a3 [2] ba a2 [2] a1 a4 [2] bd a3 [2] a1 8c }

  condition:
    any of them
}