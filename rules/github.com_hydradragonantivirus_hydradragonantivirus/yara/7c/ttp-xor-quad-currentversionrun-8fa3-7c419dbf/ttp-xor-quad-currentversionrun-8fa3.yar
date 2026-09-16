rule TTP_XOR_QUAD_CurrentVersionRun_8fa3 {
  strings:
    $key_8fa3 = { dc cc [2] f8 c2 [2] d3 ee [2] fd cc [2] e9 d7 [2] e6 cd [2] f8 d0 [2] fa d1 [2] e1 d7 [2] fd d0 [2] e1 ff }

  condition:
    any of them
}