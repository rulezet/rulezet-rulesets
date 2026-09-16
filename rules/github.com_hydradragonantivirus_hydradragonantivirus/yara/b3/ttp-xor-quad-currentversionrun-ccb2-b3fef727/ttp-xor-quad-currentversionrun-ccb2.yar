rule TTP_XOR_QUAD_CurrentVersionRun_ccb2 {
  strings:
    $key_ccb2 = { 9f dd [2] bb d3 [2] 90 ff [2] be dd [2] aa c6 [2] a5 dc [2] bb c1 [2] b9 c0 [2] a2 c6 [2] be c1 [2] a2 ee }

  condition:
    any of them
}