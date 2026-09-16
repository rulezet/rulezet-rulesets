rule TTP_XOR_QUAD_CurrentVersionRun_e59e {
  strings:
    $key_e59e = { b6 f1 [2] 92 ff [2] b9 d3 [2] 97 f1 [2] 83 ea [2] 8c f0 [2] 92 ed [2] 90 ec [2] 8b ea [2] 97 ed [2] 8b c2 }

  condition:
    any of them
}