rule TTP_XOR_QUAD_CurrentVersionRun_6d9e {
  strings:
    $key_6d9e = { 3e f1 [2] 1a ff [2] 31 d3 [2] 1f f1 [2] 0b ea [2] 04 f0 [2] 1a ed [2] 18 ec [2] 03 ea [2] 1f ed [2] 03 c2 }

  condition:
    any of them
}