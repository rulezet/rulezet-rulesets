rule TTP_XOR_QUAD_CurrentVersionRun_c593 {
  strings:
    $key_c593 = { 96 fc [2] b2 f2 [2] 99 de [2] b7 fc [2] a3 e7 [2] ac fd [2] b2 e0 [2] b0 e1 [2] ab e7 [2] b7 e0 [2] ab cf }

  condition:
    any of them
}