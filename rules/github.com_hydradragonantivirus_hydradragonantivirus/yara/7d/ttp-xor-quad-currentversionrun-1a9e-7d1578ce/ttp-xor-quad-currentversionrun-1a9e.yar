rule TTP_XOR_QUAD_CurrentVersionRun_1a9e {
  strings:
    $key_1a9e = { 49 f1 [2] 6d ff [2] 46 d3 [2] 68 f1 [2] 7c ea [2] 73 f0 [2] 6d ed [2] 6f ec [2] 74 ea [2] 68 ed [2] 74 c2 }

  condition:
    any of them
}