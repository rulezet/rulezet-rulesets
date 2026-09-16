rule TTP_XOR_QUAD_CurrentVersionRun_de8a {
  strings:
    $key_de8a = { 8d e5 [2] a9 eb [2] 82 c7 [2] ac e5 [2] b8 fe [2] b7 e4 [2] a9 f9 [2] ab f8 [2] b0 fe [2] ac f9 [2] b0 d6 }

  condition:
    any of them
}