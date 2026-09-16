rule TTP_XOR_QUAD_CurrentVersionRun_ee9e {
  strings:
    $key_ee9e = { bd f1 [2] 99 ff [2] b2 d3 [2] 9c f1 [2] 88 ea [2] 87 f0 [2] 99 ed [2] 9b ec [2] 80 ea [2] 9c ed [2] 80 c2 }

  condition:
    any of them
}