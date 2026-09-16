rule TTP_XOR_QUAD_CurrentVersionRun_cea0 {
  strings:
    $key_cea0 = { 9d cf [2] b9 c1 [2] 92 ed [2] bc cf [2] a8 d4 [2] a7 ce [2] b9 d3 [2] bb d2 [2] a0 d4 [2] bc d3 [2] a0 fc }

  condition:
    any of them
}