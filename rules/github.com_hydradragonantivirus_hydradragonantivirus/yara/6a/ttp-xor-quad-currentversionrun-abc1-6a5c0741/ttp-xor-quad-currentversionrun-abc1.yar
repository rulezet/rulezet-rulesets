rule TTP_XOR_QUAD_CurrentVersionRun_abc1 {
  strings:
    $key_abc1 = { f8 ae [2] dc a0 [2] f7 8c [2] d9 ae [2] cd b5 [2] c2 af [2] dc b2 [2] de b3 [2] c5 b5 [2] d9 b2 [2] c5 9d }

  condition:
    any of them
}