rule TTP_XOR_QUAD_CurrentVersionRun_c883 {
  strings:
    $key_c883 = { 9b ec [2] bf e2 [2] 94 ce [2] ba ec [2] ae f7 [2] a1 ed [2] bf f0 [2] bd f1 [2] a6 f7 [2] ba f0 [2] a6 df }

  condition:
    any of them
}