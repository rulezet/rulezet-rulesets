rule TTP_XOR_QUAD_CurrentVersionRun_a0a5 {
  strings:
    $key_a0a5 = { f3 ca [2] d7 c4 [2] fc e8 [2] d2 ca [2] c6 d1 [2] c9 cb [2] d7 d6 [2] d5 d7 [2] ce d1 [2] d2 d6 [2] ce f9 }

  condition:
    any of them
}