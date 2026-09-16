rule TTP_XOR_QUAD_CurrentVersionRun_85b2 {
  strings:
    $key_85b2 = { d6 dd [2] f2 d3 [2] d9 ff [2] f7 dd [2] e3 c6 [2] ec dc [2] f2 c1 [2] f0 c0 [2] eb c6 [2] f7 c1 [2] eb ee }

  condition:
    any of them
}