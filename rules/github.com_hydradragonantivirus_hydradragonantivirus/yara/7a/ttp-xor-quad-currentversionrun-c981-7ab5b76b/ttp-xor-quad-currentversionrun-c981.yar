rule TTP_XOR_QUAD_CurrentVersionRun_c981 {
  strings:
    $key_c981 = { 9a ee [2] be e0 [2] 95 cc [2] bb ee [2] af f5 [2] a0 ef [2] be f2 [2] bc f3 [2] a7 f5 [2] bb f2 [2] a7 dd }

  condition:
    any of them
}