rule TTP_XOR_QUAD_CurrentVersionRun_93b2 {
  strings:
    $key_93b2 = { c0 dd [2] e4 d3 [2] cf ff [2] e1 dd [2] f5 c6 [2] fa dc [2] e4 c1 [2] e6 c0 [2] fd c6 [2] e1 c1 [2] fd ee }

  condition:
    any of them
}