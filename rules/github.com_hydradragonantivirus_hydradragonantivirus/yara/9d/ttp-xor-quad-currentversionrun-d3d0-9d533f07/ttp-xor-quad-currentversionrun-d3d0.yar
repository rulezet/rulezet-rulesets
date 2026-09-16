rule TTP_XOR_QUAD_CurrentVersionRun_d3d0 {
  strings:
    $key_d3d0 = { 80 bf [2] a4 b1 [2] 8f 9d [2] a1 bf [2] b5 a4 [2] ba be [2] a4 a3 [2] a6 a2 [2] bd a4 [2] a1 a3 [2] bd 8c }

  condition:
    any of them
}