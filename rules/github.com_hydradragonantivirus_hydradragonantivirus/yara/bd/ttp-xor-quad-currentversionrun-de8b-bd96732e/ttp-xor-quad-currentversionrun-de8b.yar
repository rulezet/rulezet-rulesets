rule TTP_XOR_QUAD_CurrentVersionRun_de8b {
  strings:
    $key_de8b = { 8d e4 [2] a9 ea [2] 82 c6 [2] ac e4 [2] b8 ff [2] b7 e5 [2] a9 f8 [2] ab f9 [2] b0 ff [2] ac f8 [2] b0 d7 }

  condition:
    any of them
}