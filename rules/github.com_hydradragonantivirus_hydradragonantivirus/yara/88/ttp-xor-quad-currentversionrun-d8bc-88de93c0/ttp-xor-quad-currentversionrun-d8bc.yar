rule TTP_XOR_QUAD_CurrentVersionRun_d8bc {
  strings:
    $key_d8bc = { 8b d3 [2] af dd [2] 84 f1 [2] aa d3 [2] be c8 [2] b1 d2 [2] af cf [2] ad ce [2] b6 c8 [2] aa cf [2] b6 e0 }

  condition:
    any of them
}