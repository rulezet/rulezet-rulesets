rule TTP_XOR_QUAD_CurrentVersionRun_c9a0 {
  strings:
    $key_c9a0 = { 9a cf [2] be c1 [2] 95 ed [2] bb cf [2] af d4 [2] a0 ce [2] be d3 [2] bc d2 [2] a7 d4 [2] bb d3 [2] a7 fc }

  condition:
    any of them
}