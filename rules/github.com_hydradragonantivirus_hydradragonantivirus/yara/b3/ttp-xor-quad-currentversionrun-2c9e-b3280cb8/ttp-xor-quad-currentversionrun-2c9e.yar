rule TTP_XOR_QUAD_CurrentVersionRun_2c9e {
  strings:
    $key_2c9e = { 7f f1 [2] 5b ff [2] 70 d3 [2] 5e f1 [2] 4a ea [2] 45 f0 [2] 5b ed [2] 59 ec [2] 42 ea [2] 5e ed [2] 42 c2 }

  condition:
    any of them
}