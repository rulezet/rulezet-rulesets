rule TTP_XOR_QUAD_CurrentVersionRun_ab99 {
  strings:
    $key_ab99 = { f8 f6 [2] dc f8 [2] f7 d4 [2] d9 f6 [2] cd ed [2] c2 f7 [2] dc ea [2] de eb [2] c5 ed [2] d9 ea [2] c5 c5 }

  condition:
    any of them
}