rule TTP_XOR_QUAD_CurrentVersionRun_f29e {
  strings:
    $key_f29e = { a1 f1 [2] 85 ff [2] ae d3 [2] 80 f1 [2] 94 ea [2] 9b f0 [2] 85 ed [2] 87 ec [2] 9c ea [2] 80 ed [2] 9c c2 }

  condition:
    any of them
}