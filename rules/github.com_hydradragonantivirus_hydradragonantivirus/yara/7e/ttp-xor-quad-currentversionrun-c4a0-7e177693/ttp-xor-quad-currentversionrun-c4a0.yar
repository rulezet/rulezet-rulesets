rule TTP_XOR_QUAD_CurrentVersionRun_c4a0 {
  strings:
    $key_c4a0 = { 97 cf [2] b3 c1 [2] 98 ed [2] b6 cf [2] a2 d4 [2] ad ce [2] b3 d3 [2] b1 d2 [2] aa d4 [2] b6 d3 [2] aa fc }

  condition:
    any of them
}