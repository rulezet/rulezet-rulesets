rule TTP_XOR_QUAD_CurrentVersionRun_ccb4 {
  strings:
    $key_ccb4 = { 9f db [2] bb d5 [2] 90 f9 [2] be db [2] aa c0 [2] a5 da [2] bb c7 [2] b9 c6 [2] a2 c0 [2] be c7 [2] a2 e8 }

  condition:
    any of them
}