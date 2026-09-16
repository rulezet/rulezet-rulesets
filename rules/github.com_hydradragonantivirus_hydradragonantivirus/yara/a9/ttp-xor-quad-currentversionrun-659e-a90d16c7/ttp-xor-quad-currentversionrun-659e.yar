rule TTP_XOR_QUAD_CurrentVersionRun_659e {
  strings:
    $key_659e = { 36 f1 [2] 12 ff [2] 39 d3 [2] 17 f1 [2] 03 ea [2] 0c f0 [2] 12 ed [2] 10 ec [2] 0b ea [2] 17 ed [2] 0b c2 }

  condition:
    any of them
}