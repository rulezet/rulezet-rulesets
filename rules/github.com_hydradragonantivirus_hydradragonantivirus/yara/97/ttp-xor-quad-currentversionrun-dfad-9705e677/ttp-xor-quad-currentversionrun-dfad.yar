rule TTP_XOR_QUAD_CurrentVersionRun_dfad {
  strings:
    $key_dfad = { 8c c2 [2] a8 cc [2] 83 e0 [2] ad c2 [2] b9 d9 [2] b6 c3 [2] a8 de [2] aa df [2] b1 d9 [2] ad de [2] b1 f1 }

  condition:
    any of them
}