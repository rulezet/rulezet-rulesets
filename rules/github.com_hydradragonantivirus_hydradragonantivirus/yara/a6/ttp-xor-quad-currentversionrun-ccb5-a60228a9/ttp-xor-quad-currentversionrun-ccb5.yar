rule TTP_XOR_QUAD_CurrentVersionRun_ccb5 {
  strings:
    $key_ccb5 = { 9f da [2] bb d4 [2] 90 f8 [2] be da [2] aa c1 [2] a5 db [2] bb c6 [2] b9 c7 [2] a2 c1 [2] be c6 [2] a2 e9 }

  condition:
    any of them
}