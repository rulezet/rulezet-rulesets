rule TTP_XOR_QUAD_CurrentVersionRun_cabc {
  strings:
    $key_cabc = { 99 d3 [2] bd dd [2] 96 f1 [2] b8 d3 [2] ac c8 [2] a3 d2 [2] bd cf [2] bf ce [2] a4 c8 [2] b8 cf [2] a4 e0 }

  condition:
    any of them
}