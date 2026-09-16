rule TTP_XOR_QUAD_CurrentVersionRun_de9c {
  strings:
    $key_de9c = { 8d f3 [2] a9 fd [2] 82 d1 [2] ac f3 [2] b8 e8 [2] b7 f2 [2] a9 ef [2] ab ee [2] b0 e8 [2] ac ef [2] b0 c0 }

  condition:
    any of them
}