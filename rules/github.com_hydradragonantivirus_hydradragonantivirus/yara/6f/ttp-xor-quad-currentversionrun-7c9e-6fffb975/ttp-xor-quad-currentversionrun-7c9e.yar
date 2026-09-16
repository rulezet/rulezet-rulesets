rule TTP_XOR_QUAD_CurrentVersionRun_7c9e {
  strings:
    $key_7c9e = { 2f f1 [2] 0b ff [2] 20 d3 [2] 0e f1 [2] 1a ea [2] 15 f0 [2] 0b ed [2] 09 ec [2] 12 ea [2] 0e ed [2] 12 c2 }

  condition:
    any of them
}