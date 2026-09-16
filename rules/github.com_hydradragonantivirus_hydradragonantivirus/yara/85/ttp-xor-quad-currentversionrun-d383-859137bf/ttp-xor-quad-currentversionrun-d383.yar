rule TTP_XOR_QUAD_CurrentVersionRun_d383 {
  strings:
    $key_d383 = { 80 ec [2] a4 e2 [2] 8f ce [2] a1 ec [2] b5 f7 [2] ba ed [2] a4 f0 [2] a6 f1 [2] bd f7 [2] a1 f0 [2] bd df }

  condition:
    any of them
}