rule TTP_XOR_QUAD_CurrentVersionRun_d79e {
  strings:
    $key_d79e = { 84 f1 [2] a0 ff [2] 8b d3 [2] a5 f1 [2] b1 ea [2] be f0 [2] a0 ed [2] a2 ec [2] b9 ea [2] a5 ed [2] b9 c2 }

  condition:
    any of them
}