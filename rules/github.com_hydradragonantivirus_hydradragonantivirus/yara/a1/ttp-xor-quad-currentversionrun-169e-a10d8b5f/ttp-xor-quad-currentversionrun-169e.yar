rule TTP_XOR_QUAD_CurrentVersionRun_169e {
  strings:
    $key_169e = { 45 f1 [2] 61 ff [2] 4a d3 [2] 64 f1 [2] 70 ea [2] 7f f0 [2] 61 ed [2] 63 ec [2] 78 ea [2] 64 ed [2] 78 c2 }

  condition:
    any of them
}