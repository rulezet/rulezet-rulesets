rule TTP_XOR_QUAD_CurrentVersionRun_d3bb {
  strings:
    $key_d3bb = { 80 d4 [2] a4 da [2] 8f f6 [2] a1 d4 [2] b5 cf [2] ba d5 [2] a4 c8 [2] a6 c9 [2] bd cf [2] a1 c8 [2] bd e7 }

  condition:
    any of them
}