rule TTP_XOR_QUAD_CurrentVersionRun_d9a1 {
  strings:
    $key_d9a1 = { 8a ce [2] ae c0 [2] 85 ec [2] ab ce [2] bf d5 [2] b0 cf [2] ae d2 [2] ac d3 [2] b7 d5 [2] ab d2 [2] b7 fd }

  condition:
    any of them
}