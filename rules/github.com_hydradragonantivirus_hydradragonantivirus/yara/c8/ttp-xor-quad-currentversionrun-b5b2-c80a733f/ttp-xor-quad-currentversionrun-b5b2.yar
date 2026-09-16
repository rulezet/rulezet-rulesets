rule TTP_XOR_QUAD_CurrentVersionRun_b5b2 {
  strings:
    $key_b5b2 = { e6 dd [2] c2 d3 [2] e9 ff [2] c7 dd [2] d3 c6 [2] dc dc [2] c2 c1 [2] c0 c0 [2] db c6 [2] c7 c1 [2] db ee }

  condition:
    any of them
}