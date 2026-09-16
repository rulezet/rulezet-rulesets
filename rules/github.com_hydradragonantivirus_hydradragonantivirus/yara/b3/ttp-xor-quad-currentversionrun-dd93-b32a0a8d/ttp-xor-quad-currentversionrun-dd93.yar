rule TTP_XOR_QUAD_CurrentVersionRun_dd93 {
  strings:
    $key_dd93 = { 8e fc [2] aa f2 [2] 81 de [2] af fc [2] bb e7 [2] b4 fd [2] aa e0 [2] a8 e1 [2] b3 e7 [2] af e0 [2] b3 cf }

  condition:
    any of them
}