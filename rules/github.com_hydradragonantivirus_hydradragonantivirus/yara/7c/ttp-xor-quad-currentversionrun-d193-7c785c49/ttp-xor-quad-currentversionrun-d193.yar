rule TTP_XOR_QUAD_CurrentVersionRun_d193 {
  strings:
    $key_d193 = { 82 fc [2] a6 f2 [2] 8d de [2] a3 fc [2] b7 e7 [2] b8 fd [2] a6 e0 [2] a4 e1 [2] bf e7 [2] a3 e0 [2] bf cf }

  condition:
    any of them
}