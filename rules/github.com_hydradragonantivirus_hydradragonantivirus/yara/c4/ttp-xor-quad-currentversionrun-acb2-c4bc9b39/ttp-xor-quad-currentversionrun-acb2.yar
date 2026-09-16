rule TTP_XOR_QUAD_CurrentVersionRun_acb2 {
  strings:
    $key_acb2 = { ff dd [2] db d3 [2] f0 ff [2] de dd [2] ca c6 [2] c5 dc [2] db c1 [2] d9 c0 [2] c2 c6 [2] de c1 [2] c2 ee }

  condition:
    any of them
}