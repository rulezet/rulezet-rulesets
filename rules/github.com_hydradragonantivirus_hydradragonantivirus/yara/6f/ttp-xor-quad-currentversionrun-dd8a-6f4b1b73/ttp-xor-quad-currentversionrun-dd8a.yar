rule TTP_XOR_QUAD_CurrentVersionRun_dd8a {
  strings:
    $key_dd8a = { 8e e5 [2] aa eb [2] 81 c7 [2] af e5 [2] bb fe [2] b4 e4 [2] aa f9 [2] a8 f8 [2] b3 fe [2] af f9 [2] b3 d6 }

  condition:
    any of them
}