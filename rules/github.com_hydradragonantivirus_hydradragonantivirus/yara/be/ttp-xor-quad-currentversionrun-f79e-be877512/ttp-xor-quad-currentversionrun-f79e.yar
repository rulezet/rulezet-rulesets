rule TTP_XOR_QUAD_CurrentVersionRun_f79e {
  strings:
    $key_f79e = { a4 f1 [2] 80 ff [2] ab d3 [2] 85 f1 [2] 91 ea [2] 9e f0 [2] 80 ed [2] 82 ec [2] 99 ea [2] 85 ed [2] 99 c2 }

  condition:
    any of them
}