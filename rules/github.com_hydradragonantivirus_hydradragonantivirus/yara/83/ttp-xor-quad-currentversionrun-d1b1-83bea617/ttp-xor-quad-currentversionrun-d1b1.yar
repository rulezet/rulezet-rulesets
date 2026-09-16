rule TTP_XOR_QUAD_CurrentVersionRun_d1b1 {
  strings:
    $key_d1b1 = { 82 de [2] a6 d0 [2] 8d fc [2] a3 de [2] b7 c5 [2] b8 df [2] a6 c2 [2] a4 c3 [2] bf c5 [2] a3 c2 [2] bf ed }

  condition:
    any of them
}