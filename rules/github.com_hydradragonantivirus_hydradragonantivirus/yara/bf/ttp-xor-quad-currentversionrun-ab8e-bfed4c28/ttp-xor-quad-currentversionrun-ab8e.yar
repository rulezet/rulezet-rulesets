rule TTP_XOR_QUAD_CurrentVersionRun_ab8e {
  strings:
    $key_ab8e = { f8 e1 [2] dc ef [2] f7 c3 [2] d9 e1 [2] cd fa [2] c2 e0 [2] dc fd [2] de fc [2] c5 fa [2] d9 fd [2] c5 d2 }

  condition:
    any of them
}