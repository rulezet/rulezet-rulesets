rule TTP_XOR_QUAD_CurrentVersionRun_a49e {
  strings:
    $key_a49e = { f7 f1 [2] d3 ff [2] f8 d3 [2] d6 f1 [2] c2 ea [2] cd f0 [2] d3 ed [2] d1 ec [2] ca ea [2] d6 ed [2] ca c2 }

  condition:
    any of them
}