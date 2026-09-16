rule TTP_XOR_QUAD_CurrentVersionRun_dd9f {
  strings:
    $key_dd9f = { 8e f0 [2] aa fe [2] 81 d2 [2] af f0 [2] bb eb [2] b4 f1 [2] aa ec [2] a8 ed [2] b3 eb [2] af ec [2] b3 c3 }

  condition:
    any of them
}