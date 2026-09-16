rule TTP_XOR_QUAD_CurrentVersionRun_d69e {
  strings:
    $key_d69e = { 85 f1 [2] a1 ff [2] 8a d3 [2] a4 f1 [2] b0 ea [2] bf f0 [2] a1 ed [2] a3 ec [2] b8 ea [2] a4 ed [2] b8 c2 }

  condition:
    any of them
}