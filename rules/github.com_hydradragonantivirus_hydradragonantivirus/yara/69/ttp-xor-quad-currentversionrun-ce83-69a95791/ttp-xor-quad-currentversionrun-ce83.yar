rule TTP_XOR_QUAD_CurrentVersionRun_ce83 {
  strings:
    $key_ce83 = { 9d ec [2] b9 e2 [2] 92 ce [2] bc ec [2] a8 f7 [2] a7 ed [2] b9 f0 [2] bb f1 [2] a0 f7 [2] bc f0 [2] a0 df }

  condition:
    any of them
}