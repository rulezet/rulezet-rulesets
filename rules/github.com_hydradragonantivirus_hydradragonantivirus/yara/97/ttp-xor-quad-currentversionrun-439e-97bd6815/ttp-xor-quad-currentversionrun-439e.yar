rule TTP_XOR_QUAD_CurrentVersionRun_439e {
  strings:
    $key_439e = { 10 f1 [2] 34 ff [2] 1f d3 [2] 31 f1 [2] 25 ea [2] 2a f0 [2] 34 ed [2] 36 ec [2] 2d ea [2] 31 ed [2] 2d c2 }

  condition:
    any of them
}