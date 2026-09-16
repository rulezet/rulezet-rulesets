rule TTP_XOR_QUAD_CurrentVersionRun_d3bf {
  strings:
    $key_d3bf = { 80 d0 [2] a4 de [2] 8f f2 [2] a1 d0 [2] b5 cb [2] ba d1 [2] a4 cc [2] a6 cd [2] bd cb [2] a1 cc [2] bd e3 }

  condition:
    any of them
}