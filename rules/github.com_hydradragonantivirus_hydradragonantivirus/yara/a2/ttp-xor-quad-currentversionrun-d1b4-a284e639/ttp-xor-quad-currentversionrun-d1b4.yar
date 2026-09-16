rule TTP_XOR_QUAD_CurrentVersionRun_d1b4 {
  strings:
    $key_d1b4 = { 82 db [2] a6 d5 [2] 8d f9 [2] a3 db [2] b7 c0 [2] b8 da [2] a6 c7 [2] a4 c6 [2] bf c0 [2] a3 c7 [2] bf e8 }

  condition:
    any of them
}