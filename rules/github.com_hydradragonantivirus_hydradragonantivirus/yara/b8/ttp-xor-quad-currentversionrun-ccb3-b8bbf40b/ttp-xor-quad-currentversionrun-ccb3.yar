rule TTP_XOR_QUAD_CurrentVersionRun_ccb3 {
  strings:
    $key_ccb3 = { 9f dc [2] bb d2 [2] 90 fe [2] be dc [2] aa c7 [2] a5 dd [2] bb c0 [2] b9 c1 [2] a2 c7 [2] be c0 [2] a2 ef }

  condition:
    any of them
}