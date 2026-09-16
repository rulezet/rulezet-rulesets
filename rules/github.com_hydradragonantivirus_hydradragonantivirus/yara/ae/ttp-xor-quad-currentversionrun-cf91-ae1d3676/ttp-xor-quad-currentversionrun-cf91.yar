rule TTP_XOR_QUAD_CurrentVersionRun_cf91 {
  strings:
    $key_cf91 = { 9c fe [2] b8 f0 [2] 93 dc [2] bd fe [2] a9 e5 [2] a6 ff [2] b8 e2 [2] ba e3 [2] a1 e5 [2] bd e2 [2] a1 cd }

  condition:
    any of them
}