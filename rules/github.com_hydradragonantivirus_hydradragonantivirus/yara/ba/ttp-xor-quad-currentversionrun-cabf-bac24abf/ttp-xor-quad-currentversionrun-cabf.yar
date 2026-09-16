rule TTP_XOR_QUAD_CurrentVersionRun_cabf {
  strings:
    $key_cabf = { 99 d0 [2] bd de [2] 96 f2 [2] b8 d0 [2] ac cb [2] a3 d1 [2] bd cc [2] bf cd [2] a4 cb [2] b8 cc [2] a4 e3 }

  condition:
    any of them
}