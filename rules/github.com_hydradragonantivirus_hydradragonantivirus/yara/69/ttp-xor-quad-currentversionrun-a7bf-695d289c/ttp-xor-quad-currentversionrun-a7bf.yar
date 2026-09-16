rule TTP_XOR_QUAD_CurrentVersionRun_a7bf {
  strings:
    $key_a7bf = { f4 d0 [2] d0 de [2] fb f2 [2] d5 d0 [2] c1 cb [2] ce d1 [2] d0 cc [2] d2 cd [2] c9 cb [2] d5 cc [2] c9 e3 }

  condition:
    any of them
}