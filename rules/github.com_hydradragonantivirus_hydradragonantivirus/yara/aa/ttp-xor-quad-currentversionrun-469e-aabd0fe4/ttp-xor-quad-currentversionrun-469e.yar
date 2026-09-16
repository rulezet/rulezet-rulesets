rule TTP_XOR_QUAD_CurrentVersionRun_469e {
  strings:
    $key_469e = { 15 f1 [2] 31 ff [2] 1a d3 [2] 34 f1 [2] 20 ea [2] 2f f0 [2] 31 ed [2] 33 ec [2] 28 ea [2] 34 ed [2] 28 c2 }

  condition:
    any of them
}