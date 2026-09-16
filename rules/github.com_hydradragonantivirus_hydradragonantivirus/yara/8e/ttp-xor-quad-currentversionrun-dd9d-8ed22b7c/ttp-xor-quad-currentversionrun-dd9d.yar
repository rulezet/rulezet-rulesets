rule TTP_XOR_QUAD_CurrentVersionRun_dd9d {
  strings:
    $key_dd9d = { 8e f2 [2] aa fc [2] 81 d0 [2] af f2 [2] bb e9 [2] b4 f3 [2] aa ee [2] a8 ef [2] b3 e9 [2] af ee [2] b3 c1 }

  condition:
    any of them
}