rule TTP_XOR_QUAD_CurrentVersionRun_a3bf {
  strings:
    $key_a3bf = { f0 d0 [2] d4 de [2] ff f2 [2] d1 d0 [2] c5 cb [2] ca d1 [2] d4 cc [2] d6 cd [2] cd cb [2] d1 cc [2] cd e3 }

  condition:
    any of them
}