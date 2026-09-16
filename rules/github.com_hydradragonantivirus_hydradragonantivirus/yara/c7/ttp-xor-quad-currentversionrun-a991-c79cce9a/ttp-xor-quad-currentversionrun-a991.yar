rule TTP_XOR_QUAD_CurrentVersionRun_a991 {
  strings:
    $key_a991 = { fa fe [2] de f0 [2] f5 dc [2] db fe [2] cf e5 [2] c0 ff [2] de e2 [2] dc e3 [2] c7 e5 [2] db e2 [2] c7 cd }

  condition:
    any of them
}