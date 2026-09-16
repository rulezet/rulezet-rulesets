rule TTP_XOR_QUAD_CurrentVersionRun_b4b2 {
  strings:
    $key_b4b2 = { e7 dd [2] c3 d3 [2] e8 ff [2] c6 dd [2] d2 c6 [2] dd dc [2] c3 c1 [2] c1 c0 [2] da c6 [2] c6 c1 [2] da ee }

  condition:
    any of them
}