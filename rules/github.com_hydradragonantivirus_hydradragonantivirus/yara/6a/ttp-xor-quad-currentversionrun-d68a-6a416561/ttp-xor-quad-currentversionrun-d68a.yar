rule TTP_XOR_QUAD_CurrentVersionRun_d68a {
  strings:
    $key_d68a = { 85 e5 [2] a1 eb [2] 8a c7 [2] a4 e5 [2] b0 fe [2] bf e4 [2] a1 f9 [2] a3 f8 [2] b8 fe [2] a4 f9 [2] b8 d6 }

  condition:
    any of them
}