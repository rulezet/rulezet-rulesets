rule TTP_XOR_QUAD_CurrentVersionRun_abd6 {
  strings:
    $key_abd6 = { f8 b9 [2] dc b7 [2] f7 9b [2] d9 b9 [2] cd a2 [2] c2 b8 [2] dc a5 [2] de a4 [2] c5 a2 [2] d9 a5 [2] c5 8a }

  condition:
    any of them
}