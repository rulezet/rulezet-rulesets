rule TTP_XOR_QUAD_CurrentVersionRun_cc9e {
  strings:
    $key_cc9e = { 9f f1 [2] bb ff [2] 90 d3 [2] be f1 [2] aa ea [2] a5 f0 [2] bb ed [2] b9 ec [2] a2 ea [2] be ed [2] a2 c2 }

  condition:
    any of them
}