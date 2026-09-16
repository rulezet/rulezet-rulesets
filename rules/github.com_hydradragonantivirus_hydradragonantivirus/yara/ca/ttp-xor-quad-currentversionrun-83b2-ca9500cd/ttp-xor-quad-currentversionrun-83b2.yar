rule TTP_XOR_QUAD_CurrentVersionRun_83b2 {
  strings:
    $key_83b2 = { d0 dd [2] f4 d3 [2] df ff [2] f1 dd [2] e5 c6 [2] ea dc [2] f4 c1 [2] f6 c0 [2] ed c6 [2] f1 c1 [2] ed ee }

  condition:
    any of them
}