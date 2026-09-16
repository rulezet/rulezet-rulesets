rule TTP_XOR_QUAD_CurrentVersionRun_209e {
  strings:
    $key_209e = { 73 f1 [2] 57 ff [2] 7c d3 [2] 52 f1 [2] 46 ea [2] 49 f0 [2] 57 ed [2] 55 ec [2] 4e ea [2] 52 ed [2] 4e c2 }

  condition:
    any of them
}