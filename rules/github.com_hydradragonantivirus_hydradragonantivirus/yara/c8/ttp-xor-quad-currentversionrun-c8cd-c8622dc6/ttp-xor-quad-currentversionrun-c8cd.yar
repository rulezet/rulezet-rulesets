rule TTP_XOR_QUAD_CurrentVersionRun_c8cd {
  strings:
    $key_c8cd = { 9b a2 [2] bf ac [2] 94 80 [2] ba a2 [2] ae b9 [2] a1 a3 [2] bf be [2] bd bf [2] a6 b9 [2] ba be [2] a6 91 }

  condition:
    any of them
}