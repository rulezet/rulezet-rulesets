rule TTP_XOR_QUAD_CurrentVersionRun_af87 {
  strings:
    $key_af87 = { fc e8 [2] d8 e6 [2] f3 ca [2] dd e8 [2] c9 f3 [2] c6 e9 [2] d8 f4 [2] da f5 [2] c1 f3 [2] dd f4 [2] c1 db }

  condition:
    any of them
}