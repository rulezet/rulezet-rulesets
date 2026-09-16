rule TTP_XOR_QUAD_CurrentVersionRun_cf81 {
  strings:
    $key_cf81 = { 9c ee [2] b8 e0 [2] 93 cc [2] bd ee [2] a9 f5 [2] a6 ef [2] b8 f2 [2] ba f3 [2] a1 f5 [2] bd f2 [2] a1 dd }

  condition:
    any of them
}