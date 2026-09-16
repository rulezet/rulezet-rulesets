rule TTP_XOR_QUAD_CurrentVersionRun_5d9e {
  strings:
    $key_5d9e = { 0e f1 [2] 2a ff [2] 01 d3 [2] 2f f1 [2] 3b ea [2] 34 f0 [2] 2a ed [2] 28 ec [2] 33 ea [2] 2f ed [2] 33 c2 }

  condition:
    any of them
}