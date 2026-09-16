rule TTP_XOR_QUAD_CurrentVersionRun_429e {
  strings:
    $key_429e = { 11 f1 [2] 35 ff [2] 1e d3 [2] 30 f1 [2] 24 ea [2] 2b f0 [2] 35 ed [2] 37 ec [2] 2c ea [2] 30 ed [2] 2c c2 }

  condition:
    any of them
}