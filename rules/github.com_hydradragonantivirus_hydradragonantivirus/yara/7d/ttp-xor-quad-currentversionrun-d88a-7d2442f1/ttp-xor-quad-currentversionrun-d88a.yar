rule TTP_XOR_QUAD_CurrentVersionRun_d88a {
  strings:
    $key_d88a = { 8b e5 [2] af eb [2] 84 c7 [2] aa e5 [2] be fe [2] b1 e4 [2] af f9 [2] ad f8 [2] b6 fe [2] aa f9 [2] b6 d6 }

  condition:
    any of them
}