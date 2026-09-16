rule TTP_XOR_QUAD_CurrentVersionRun_dd81 {
  strings:
    $key_dd81 = { 8e ee [2] aa e0 [2] 81 cc [2] af ee [2] bb f5 [2] b4 ef [2] aa f2 [2] a8 f3 [2] b3 f5 [2] af f2 [2] b3 dd }

  condition:
    any of them
}