rule TTP_XOR_QUAD_CurrentVersionRun_ca8d {
  strings:
    $key_ca8d = { 99 e2 [2] bd ec [2] 96 c0 [2] b8 e2 [2] ac f9 [2] a3 e3 [2] bd fe [2] bf ff [2] a4 f9 [2] b8 fe [2] a4 d1 }

  condition:
    any of them
}