rule TTP_XOR_QUAD_CurrentVersionRun_559e {
  strings:
    $key_559e = { 06 f1 [2] 22 ff [2] 09 d3 [2] 27 f1 [2] 33 ea [2] 3c f0 [2] 22 ed [2] 20 ec [2] 3b ea [2] 27 ed [2] 3b c2 }

  condition:
    any of them
}