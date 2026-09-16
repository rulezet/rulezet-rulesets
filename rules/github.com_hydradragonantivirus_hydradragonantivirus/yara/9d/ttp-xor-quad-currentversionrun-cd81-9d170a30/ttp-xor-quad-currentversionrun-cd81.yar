rule TTP_XOR_QUAD_CurrentVersionRun_cd81 {
  strings:
    $key_cd81 = { 9e ee [2] ba e0 [2] 91 cc [2] bf ee [2] ab f5 [2] a4 ef [2] ba f2 [2] b8 f3 [2] a3 f5 [2] bf f2 [2] a3 dd }

  condition:
    any of them
}