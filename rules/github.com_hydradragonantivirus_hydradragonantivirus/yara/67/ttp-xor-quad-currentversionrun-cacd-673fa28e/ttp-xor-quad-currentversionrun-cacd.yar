rule TTP_XOR_QUAD_CurrentVersionRun_cacd {
  strings:
    $key_cacd = { 99 a2 [2] bd ac [2] 96 80 [2] b8 a2 [2] ac b9 [2] a3 a3 [2] bd be [2] bf bf [2] a4 b9 [2] b8 be [2] a4 91 }

  condition:
    any of them
}