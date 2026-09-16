rule TTP_XOR_QUAD_CurrentVersionRun_d883 {
  strings:
    $key_d883 = { 8b ec [2] af e2 [2] 84 ce [2] aa ec [2] be f7 [2] b1 ed [2] af f0 [2] ad f1 [2] b6 f7 [2] aa f0 [2] b6 df }

  condition:
    any of them
}