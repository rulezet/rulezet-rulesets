rule TTP_XOR_QUAD_CurrentVersionRun_629e {
  strings:
    $key_629e = { 31 f1 [2] 15 ff [2] 3e d3 [2] 10 f1 [2] 04 ea [2] 0b f0 [2] 15 ed [2] 17 ec [2] 0c ea [2] 10 ed [2] 0c c2 }

  condition:
    any of them
}