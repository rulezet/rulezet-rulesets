rule TTP_XOR_QUAD_CurrentVersionRun_de9a {
  strings:
    $key_de9a = { 8d f5 [2] a9 fb [2] 82 d7 [2] ac f5 [2] b8 ee [2] b7 f4 [2] a9 e9 [2] ab e8 [2] b0 ee [2] ac e9 [2] b0 c6 }

  condition:
    any of them
}