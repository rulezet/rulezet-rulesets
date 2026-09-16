rule TTP_XOR_QUAD_CurrentVersionRun_ccb6 {
  strings:
    $key_ccb6 = { 9f d9 [2] bb d7 [2] 90 fb [2] be d9 [2] aa c2 [2] a5 d8 [2] bb c5 [2] b9 c4 [2] a2 c2 [2] be c5 [2] a2 ea }

  condition:
    any of them
}