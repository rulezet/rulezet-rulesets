rule TTP_XOR_QUAD_CurrentVersionRun_abbf {
  strings:
    $key_abbf = { f8 d0 [2] dc de [2] f7 f2 [2] d9 d0 [2] cd cb [2] c2 d1 [2] dc cc [2] de cd [2] c5 cb [2] d9 cc [2] c5 e3 }

  condition:
    any of them
}