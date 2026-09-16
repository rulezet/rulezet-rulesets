rule TTP_XOR_QUAD_CurrentVersionRun_ca96 {
  strings:
    $key_ca96 = { 99 f9 [2] bd f7 [2] 96 db [2] b8 f9 [2] ac e2 [2] a3 f8 [2] bd e5 [2] bf e4 [2] a4 e2 [2] b8 e5 [2] a4 ca }

  condition:
    any of them
}