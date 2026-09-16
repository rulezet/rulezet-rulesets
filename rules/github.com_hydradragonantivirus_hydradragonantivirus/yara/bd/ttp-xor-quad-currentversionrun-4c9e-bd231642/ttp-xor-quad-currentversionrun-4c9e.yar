rule TTP_XOR_QUAD_CurrentVersionRun_4c9e {
  strings:
    $key_4c9e = { 1f f1 [2] 3b ff [2] 10 d3 [2] 3e f1 [2] 2a ea [2] 25 f0 [2] 3b ed [2] 39 ec [2] 22 ea [2] 3e ed [2] 22 c2 }

  condition:
    any of them
}