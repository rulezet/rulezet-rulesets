rule TTP_XOR_QUAD_CurrentVersionRun_ab8c {
  strings:
    $key_ab8c = { f8 e3 [2] dc ed [2] f7 c1 [2] d9 e3 [2] cd f8 [2] c2 e2 [2] dc ff [2] de fe [2] c5 f8 [2] d9 ff [2] c5 d0 }

  condition:
    any of them
}