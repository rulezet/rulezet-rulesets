rule TTP_XOR_QUAD_CurrentVersionRun_de93 {
  strings:
    $key_de93 = { 8d fc [2] a9 f2 [2] 82 de [2] ac fc [2] b8 e7 [2] b7 fd [2] a9 e0 [2] ab e1 [2] b0 e7 [2] ac e0 [2] b0 cf }

  condition:
    any of them
}