rule TTP_XOR_QUAD_CurrentVersionRun_c9bc {
  strings:
    $key_c9bc = { 9a d3 [2] be dd [2] 95 f1 [2] bb d3 [2] af c8 [2] a0 d2 [2] be cf [2] bc ce [2] a7 c8 [2] bb cf [2] a7 e0 }

  condition:
    any of them
}