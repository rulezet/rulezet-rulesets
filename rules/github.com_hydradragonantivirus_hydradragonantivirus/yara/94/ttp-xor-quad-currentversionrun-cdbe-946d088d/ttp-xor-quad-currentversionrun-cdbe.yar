rule TTP_XOR_QUAD_CurrentVersionRun_cdbe {
  strings:
    $key_cdbe = { 9e d1 [2] ba df [2] 91 f3 [2] bf d1 [2] ab ca [2] a4 d0 [2] ba cd [2] b8 cc [2] a3 ca [2] bf cd [2] a3 e2 }

  condition:
    any of them
}