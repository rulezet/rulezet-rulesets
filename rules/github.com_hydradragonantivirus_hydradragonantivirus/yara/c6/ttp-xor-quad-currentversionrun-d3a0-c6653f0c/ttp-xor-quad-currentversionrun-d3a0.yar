rule TTP_XOR_QUAD_CurrentVersionRun_d3a0 {
  strings:
    $key_d3a0 = { 80 cf [2] a4 c1 [2] 8f ed [2] a1 cf [2] b5 d4 [2] ba ce [2] a4 d3 [2] a6 d2 [2] bd d4 [2] a1 d3 [2] bd fc }

  condition:
    any of them
}