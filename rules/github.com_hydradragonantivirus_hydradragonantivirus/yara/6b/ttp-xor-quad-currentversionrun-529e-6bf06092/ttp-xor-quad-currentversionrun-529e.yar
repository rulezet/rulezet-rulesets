rule TTP_XOR_QUAD_CurrentVersionRun_529e {
  strings:
    $key_529e = { 01 f1 [2] 25 ff [2] 0e d3 [2] 20 f1 [2] 34 ea [2] 3b f0 [2] 25 ed [2] 27 ec [2] 3c ea [2] 20 ed [2] 3c c2 }

  condition:
    any of them
}