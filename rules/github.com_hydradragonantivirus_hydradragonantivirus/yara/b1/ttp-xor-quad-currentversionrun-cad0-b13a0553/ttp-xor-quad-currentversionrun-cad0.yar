rule TTP_XOR_QUAD_CurrentVersionRun_cad0 {
  strings:
    $key_cad0 = { 99 bf [2] bd b1 [2] 96 9d [2] b8 bf [2] ac a4 [2] a3 be [2] bd a3 [2] bf a2 [2] a4 a4 [2] b8 a3 [2] a4 8c }

  condition:
    any of them
}