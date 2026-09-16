rule TTP_XOR_QUAD_CurrentVersionRun_cdbb {
  strings:
    $key_cdbb = { 9e d4 [2] ba da [2] 91 f6 [2] bf d4 [2] ab cf [2] a4 d5 [2] ba c8 [2] b8 c9 [2] a3 cf [2] bf c8 [2] a3 e7 }

  condition:
    any of them
}