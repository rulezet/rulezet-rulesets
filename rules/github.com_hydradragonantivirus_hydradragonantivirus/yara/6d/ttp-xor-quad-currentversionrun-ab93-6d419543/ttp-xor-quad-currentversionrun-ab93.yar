rule TTP_XOR_QUAD_CurrentVersionRun_ab93 {
  strings:
    $key_ab93 = { f8 fc [2] dc f2 [2] f7 de [2] d9 fc [2] cd e7 [2] c2 fd [2] dc e0 [2] de e1 [2] c5 e7 [2] d9 e0 [2] c5 cf }

  condition:
    any of them
}