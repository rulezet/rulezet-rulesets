rule TTP_XOR_QUAD_CurrentVersionRun_1d9e {
  strings:
    $key_1d9e = { 4e f1 [2] 6a ff [2] 41 d3 [2] 6f f1 [2] 7b ea [2] 74 f0 [2] 6a ed [2] 68 ec [2] 73 ea [2] 6f ed [2] 73 c2 }

  condition:
    any of them
}