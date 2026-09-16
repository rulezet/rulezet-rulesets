rule TTP_XOR_QUAD_CurrentVersionRun_ccac {
  strings:
    $key_ccac = { 9f c3 [2] bb cd [2] 90 e1 [2] be c3 [2] aa d8 [2] a5 c2 [2] bb df [2] b9 de [2] a2 d8 [2] be df [2] a2 f0 }

  condition:
    any of them
}