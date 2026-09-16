rule TTP_XOR_QUAD_CurrentVersionRun_ab8d {
  strings:
    $key_ab8d = { f8 e2 [2] dc ec [2] f7 c0 [2] d9 e2 [2] cd f9 [2] c2 e3 [2] dc fe [2] de ff [2] c5 f9 [2] d9 fe [2] c5 d1 }

  condition:
    any of them
}