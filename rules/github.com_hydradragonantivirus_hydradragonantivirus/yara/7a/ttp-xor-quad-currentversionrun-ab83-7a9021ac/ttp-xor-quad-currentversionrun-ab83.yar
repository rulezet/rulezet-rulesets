rule TTP_XOR_QUAD_CurrentVersionRun_ab83 {
  strings:
    $key_ab83 = { f8 ec [2] dc e2 [2] f7 ce [2] d9 ec [2] cd f7 [2] c2 ed [2] dc f0 [2] de f1 [2] c5 f7 [2] d9 f0 [2] c5 df }

  condition:
    any of them
}