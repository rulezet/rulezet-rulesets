rule TTP_XOR_QUAD_CurrentVersionRun_ab9e {
  strings:
    $key_ab9e = { f8 f1 [2] dc ff [2] f7 d3 [2] d9 f1 [2] cd ea [2] c2 f0 [2] dc ed [2] de ec [2] c5 ea [2] d9 ed [2] c5 c2 }

  condition:
    any of them
}