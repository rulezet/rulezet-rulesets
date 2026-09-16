rule TTP_XOR_QUAD_CurrentVersionRun_919e {
  strings:
    $key_919e = { c2 f1 [2] e6 ff [2] cd d3 [2] e3 f1 [2] f7 ea [2] f8 f0 [2] e6 ed [2] e4 ec [2] ff ea [2] e3 ed [2] ff c2 }

  condition:
    any of them
}