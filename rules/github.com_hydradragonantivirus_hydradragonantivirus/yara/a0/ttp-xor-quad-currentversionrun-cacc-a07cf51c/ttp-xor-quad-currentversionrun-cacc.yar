rule TTP_XOR_QUAD_CurrentVersionRun_cacc {
  strings:
    $key_cacc = { 99 a3 [2] bd ad [2] 96 81 [2] b8 a3 [2] ac b8 [2] a3 a2 [2] bd bf [2] bf be [2] a4 b8 [2] b8 bf [2] a4 90 }

  condition:
    any of them
}