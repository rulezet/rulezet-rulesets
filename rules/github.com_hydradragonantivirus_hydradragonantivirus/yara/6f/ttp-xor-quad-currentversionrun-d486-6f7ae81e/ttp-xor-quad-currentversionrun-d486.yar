rule TTP_XOR_QUAD_CurrentVersionRun_d486 {
  strings:
    $key_d486 = { 87 e9 [2] a3 e7 [2] 88 cb [2] a6 e9 [2] b2 f2 [2] bd e8 [2] a3 f5 [2] a1 f4 [2] ba f2 [2] a6 f5 [2] ba da }

  condition:
    any of them
}