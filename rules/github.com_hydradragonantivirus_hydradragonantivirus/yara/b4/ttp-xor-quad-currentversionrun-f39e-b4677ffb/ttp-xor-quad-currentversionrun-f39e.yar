rule TTP_XOR_QUAD_CurrentVersionRun_f39e {
  strings:
    $key_f39e = { a0 f1 [2] 84 ff [2] af d3 [2] 81 f1 [2] 95 ea [2] 9a f0 [2] 84 ed [2] 86 ec [2] 9d ea [2] 81 ed [2] 9d c2 }

  condition:
    any of them
}