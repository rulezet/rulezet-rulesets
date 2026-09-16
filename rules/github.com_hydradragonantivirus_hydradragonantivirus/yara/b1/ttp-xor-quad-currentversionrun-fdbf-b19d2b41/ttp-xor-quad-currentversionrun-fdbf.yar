rule TTP_XOR_QUAD_CurrentVersionRun_fdbf {
  strings:
    $key_fdbf = { ae d0 [2] 8a de [2] a1 f2 [2] 8f d0 [2] 9b cb [2] 94 d1 [2] 8a cc [2] 88 cd [2] 93 cb [2] 8f cc [2] 93 e3 }

  condition:
    any of them
}