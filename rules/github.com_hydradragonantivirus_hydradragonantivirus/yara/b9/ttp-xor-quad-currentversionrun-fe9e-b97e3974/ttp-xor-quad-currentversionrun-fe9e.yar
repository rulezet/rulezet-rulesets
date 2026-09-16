rule TTP_XOR_QUAD_CurrentVersionRun_fe9e {
  strings:
    $key_fe9e = { ad f1 [2] 89 ff [2] a2 d3 [2] 8c f1 [2] 98 ea [2] 97 f0 [2] 89 ed [2] 8b ec [2] 90 ea [2] 8c ed [2] 90 c2 }

  condition:
    any of them
}