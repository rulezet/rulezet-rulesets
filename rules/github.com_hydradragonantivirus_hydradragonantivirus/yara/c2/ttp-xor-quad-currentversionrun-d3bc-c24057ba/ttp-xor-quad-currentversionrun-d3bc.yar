rule TTP_XOR_QUAD_CurrentVersionRun_d3bc {
  strings:
    $key_d3bc = { 80 d3 [2] a4 dd [2] 8f f1 [2] a1 d3 [2] b5 c8 [2] ba d2 [2] a4 cf [2] a6 ce [2] bd c8 [2] a1 cf [2] bd e0 }

  condition:
    any of them
}