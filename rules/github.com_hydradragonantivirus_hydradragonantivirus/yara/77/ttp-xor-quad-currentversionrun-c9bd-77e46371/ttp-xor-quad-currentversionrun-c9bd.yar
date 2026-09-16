rule TTP_XOR_QUAD_CurrentVersionRun_c9bd {
  strings:
    $key_c9bd = { 9a d2 [2] be dc [2] 95 f0 [2] bb d2 [2] af c9 [2] a0 d3 [2] be ce [2] bc cf [2] a7 c9 [2] bb ce [2] a7 e1 }

  condition:
    any of them
}