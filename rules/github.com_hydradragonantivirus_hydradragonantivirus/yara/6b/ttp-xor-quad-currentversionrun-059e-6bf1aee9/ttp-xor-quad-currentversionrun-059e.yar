rule TTP_XOR_QUAD_CurrentVersionRun_059e {
  strings:
    $key_059e = { 56 f1 [2] 72 ff [2] 59 d3 [2] 77 f1 [2] 63 ea [2] 6c f0 [2] 72 ed [2] 70 ec [2] 6b ea [2] 77 ed [2] 6b c2 }

  condition:
    any of them
}