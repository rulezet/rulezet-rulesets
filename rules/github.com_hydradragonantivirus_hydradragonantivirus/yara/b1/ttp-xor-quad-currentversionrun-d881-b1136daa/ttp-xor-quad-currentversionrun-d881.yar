rule TTP_XOR_QUAD_CurrentVersionRun_d881 {
  strings:
    $key_d881 = { 8b ee [2] af e0 [2] 84 cc [2] aa ee [2] be f5 [2] b1 ef [2] af f2 [2] ad f3 [2] b6 f5 [2] aa f2 [2] b6 dd }

  condition:
    any of them
}