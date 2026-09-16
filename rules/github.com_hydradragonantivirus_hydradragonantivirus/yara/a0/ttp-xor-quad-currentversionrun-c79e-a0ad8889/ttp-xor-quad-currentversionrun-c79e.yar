rule TTP_XOR_QUAD_CurrentVersionRun_c79e {
  strings:
    $key_c79e = { 94 f1 [2] b0 ff [2] 9b d3 [2] b5 f1 [2] a1 ea [2] ae f0 [2] b0 ed [2] b2 ec [2] a9 ea [2] b5 ed [2] a9 c2 }

  condition:
    any of them
}