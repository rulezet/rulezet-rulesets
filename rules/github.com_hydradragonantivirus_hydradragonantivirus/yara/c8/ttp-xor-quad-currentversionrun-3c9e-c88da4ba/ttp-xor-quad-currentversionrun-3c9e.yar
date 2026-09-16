rule TTP_XOR_QUAD_CurrentVersionRun_3c9e {
  strings:
    $key_3c9e = { 6f f1 [2] 4b ff [2] 60 d3 [2] 4e f1 [2] 5a ea [2] 55 f0 [2] 4b ed [2] 49 ec [2] 52 ea [2] 4e ed [2] 52 c2 }

  condition:
    any of them
}