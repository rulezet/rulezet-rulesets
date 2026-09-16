rule TTP_XOR_QUAD_CurrentVersionRun_4d9e {
  strings:
    $key_4d9e = { 1e f1 [2] 3a ff [2] 11 d3 [2] 3f f1 [2] 2b ea [2] 24 f0 [2] 3a ed [2] 38 ec [2] 23 ea [2] 3f ed [2] 23 c2 }

  condition:
    any of them
}