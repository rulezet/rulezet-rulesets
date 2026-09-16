rule TTP_XOR_QUAD_CurrentVersionRun_5c9e {
  strings:
    $key_5c9e = { 0f f1 [2] 2b ff [2] 00 d3 [2] 2e f1 [2] 3a ea [2] 35 f0 [2] 2b ed [2] 29 ec [2] 32 ea [2] 2e ed [2] 32 c2 }

  condition:
    any of them
}