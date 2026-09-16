rule TTP_XOR_QUAD_CurrentVersionRun_ec9e {
  strings:
    $key_ec9e = { bf f1 [2] 9b ff [2] b0 d3 [2] 9e f1 [2] 8a ea [2] 85 f0 [2] 9b ed [2] 99 ec [2] 82 ea [2] 9e ed [2] 82 c2 }

  condition:
    any of them
}