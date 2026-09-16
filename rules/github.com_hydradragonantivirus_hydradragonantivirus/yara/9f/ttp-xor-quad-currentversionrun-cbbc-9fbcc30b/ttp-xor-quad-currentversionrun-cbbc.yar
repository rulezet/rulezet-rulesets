rule TTP_XOR_QUAD_CurrentVersionRun_cbbc {
  strings:
    $key_cbbc = { 98 d3 [2] bc dd [2] 97 f1 [2] b9 d3 [2] ad c8 [2] a2 d2 [2] bc cf [2] be ce [2] a5 c8 [2] b9 cf [2] a5 e0 }

  condition:
    any of them
}