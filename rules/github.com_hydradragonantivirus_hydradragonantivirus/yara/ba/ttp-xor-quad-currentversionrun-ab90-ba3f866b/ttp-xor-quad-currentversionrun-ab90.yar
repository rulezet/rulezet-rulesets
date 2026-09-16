rule TTP_XOR_QUAD_CurrentVersionRun_ab90 {
  strings:
    $key_ab90 = { f8 ff [2] dc f1 [2] f7 dd [2] d9 ff [2] cd e4 [2] c2 fe [2] dc e3 [2] de e2 [2] c5 e4 [2] d9 e3 [2] c5 cc }

  condition:
    any of them
}