rule TTP_XOR_QUAD_CurrentVersionRun_cf83 {
  strings:
    $key_cf83 = { 9c ec [2] b8 e2 [2] 93 ce [2] bd ec [2] a9 f7 [2] a6 ed [2] b8 f0 [2] ba f1 [2] a1 f7 [2] bd f0 [2] a1 df }

  condition:
    any of them
}