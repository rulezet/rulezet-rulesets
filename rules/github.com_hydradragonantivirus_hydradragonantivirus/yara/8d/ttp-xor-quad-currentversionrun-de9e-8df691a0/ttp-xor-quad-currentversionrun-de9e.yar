rule TTP_XOR_QUAD_CurrentVersionRun_de9e {
  strings:
    $key_de9e = { 8d f1 [2] a9 ff [2] 82 d3 [2] ac f1 [2] b8 ea [2] b7 f0 [2] a9 ed [2] ab ec [2] b0 ea [2] ac ed [2] b0 c2 }

  condition:
    any of them
}