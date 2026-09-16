rule TTP_XOR_QUAD_CurrentVersionRun_cad1 {
  strings:
    $key_cad1 = { 99 be [2] bd b0 [2] 96 9c [2] b8 be [2] ac a5 [2] a3 bf [2] bd a2 [2] bf a3 [2] a4 a5 [2] b8 a2 [2] a4 8d }

  condition:
    any of them
}