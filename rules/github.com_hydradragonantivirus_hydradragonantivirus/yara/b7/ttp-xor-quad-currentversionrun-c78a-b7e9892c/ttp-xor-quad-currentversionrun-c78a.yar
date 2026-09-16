rule TTP_XOR_QUAD_CurrentVersionRun_c78a {
  strings:
    $key_c78a = { 94 e5 [2] b0 eb [2] 9b c7 [2] b5 e5 [2] a1 fe [2] ae e4 [2] b0 f9 [2] b2 f8 [2] a9 fe [2] b5 f9 [2] a9 d6 }

  condition:
    any of them
}