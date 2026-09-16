rule TTP_XOR_QUAD_CurrentVersionRun_0d9e {
  strings:
    $key_0d9e = { 5e f1 [2] 7a ff [2] 51 d3 [2] 7f f1 [2] 6b ea [2] 64 f0 [2] 7a ed [2] 78 ec [2] 63 ea [2] 7f ed [2] 63 c2 }

  condition:
    any of them
}