rule TTP_XOR_QUAD_CurrentVersionRun_c49e {
  strings:
    $key_c49e = { 97 f1 [2] b3 ff [2] 98 d3 [2] b6 f1 [2] a2 ea [2] ad f0 [2] b3 ed [2] b1 ec [2] aa ea [2] b6 ed [2] aa c2 }

  condition:
    any of them
}