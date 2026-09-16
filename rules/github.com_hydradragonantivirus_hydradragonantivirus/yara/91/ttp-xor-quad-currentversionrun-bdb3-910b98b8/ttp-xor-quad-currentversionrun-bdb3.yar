rule TTP_XOR_QUAD_CurrentVersionRun_bdb3 {
  strings:
    $key_bdb3 = { ee dc [2] ca d2 [2] e1 fe [2] cf dc [2] db c7 [2] d4 dd [2] ca c0 [2] c8 c1 [2] d3 c7 [2] cf c0 [2] d3 ef }

  condition:
    any of them
}