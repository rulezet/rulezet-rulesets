rule TTP_XOR_QUAD_CurrentVersionRun_cf82 {
  strings:
    $key_cf82 = { 9c ed [2] b8 e3 [2] 93 cf [2] bd ed [2] a9 f6 [2] a6 ec [2] b8 f1 [2] ba f0 [2] a1 f6 [2] bd f1 [2] a1 de }

  condition:
    any of them
}