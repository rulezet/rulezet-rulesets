rule TTP_XOR_QUAD_CurrentVersionRun_c09e {
  strings:
    $key_c09e = { 93 f1 [2] b7 ff [2] 9c d3 [2] b2 f1 [2] a6 ea [2] a9 f0 [2] b7 ed [2] b5 ec [2] ae ea [2] b2 ed [2] ae c2 }

  condition:
    any of them
}