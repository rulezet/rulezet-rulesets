rule TTP_XOR_QUAD_CurrentVersionRun_c68a {
  strings:
    $key_c68a = { 95 e5 [2] b1 eb [2] 9a c7 [2] b4 e5 [2] a0 fe [2] af e4 [2] b1 f9 [2] b3 f8 [2] a8 fe [2] b4 f9 [2] a8 d6 }

  condition:
    any of them
}