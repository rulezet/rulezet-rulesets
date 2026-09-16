rule TTP_XOR_QUAD_CurrentVersionRun_dcbd {
  strings:
    $key_dcbd = { 8f d2 [2] ab dc [2] 80 f0 [2] ae d2 [2] ba c9 [2] b5 d3 [2] ab ce [2] a9 cf [2] b2 c9 [2] ae ce [2] b2 e1 }

  condition:
    any of them
}