rule TTP_XOR_QUAD_CurrentVersionRun_de98 {
  strings:
    $key_de98 = { 8d f7 [2] a9 f9 [2] 82 d5 [2] ac f7 [2] b8 ec [2] b7 f6 [2] a9 eb [2] ab ea [2] b0 ec [2] ac eb [2] b0 c4 }

  condition:
    any of them
}