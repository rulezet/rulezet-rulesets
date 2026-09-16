rule TTP_XOR_QUAD_CurrentVersionRun_abc0 {
  strings:
    $key_abc0 = { f8 af [2] dc a1 [2] f7 8d [2] d9 af [2] cd b4 [2] c2 ae [2] dc b3 [2] de b2 [2] c5 b4 [2] d9 b3 [2] c5 9c }

  condition:
    any of them
}