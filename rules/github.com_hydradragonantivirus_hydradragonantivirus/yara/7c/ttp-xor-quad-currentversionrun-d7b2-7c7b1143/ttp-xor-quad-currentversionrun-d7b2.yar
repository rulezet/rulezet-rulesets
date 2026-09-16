rule TTP_XOR_QUAD_CurrentVersionRun_d7b2 {
  strings:
    $key_d7b2 = { 84 dd [2] a0 d3 [2] 8b ff [2] a5 dd [2] b1 c6 [2] be dc [2] a0 c1 [2] a2 c0 [2] b9 c6 [2] a5 c1 [2] b9 ee }

  condition:
    any of them
}