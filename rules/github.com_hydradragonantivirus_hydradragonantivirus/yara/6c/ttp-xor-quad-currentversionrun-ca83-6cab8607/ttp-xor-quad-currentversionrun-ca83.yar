rule TTP_XOR_QUAD_CurrentVersionRun_ca83 {
  strings:
    $key_ca83 = { 99 ec [2] bd e2 [2] 96 ce [2] b8 ec [2] ac f7 [2] a3 ed [2] bd f0 [2] bf f1 [2] a4 f7 [2] b8 f0 [2] a4 df }

  condition:
    any of them
}