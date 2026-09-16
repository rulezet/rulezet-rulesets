rule TTP_XOR_QUAD_CurrentVersionRun_c8be {
  strings:
    $key_c8be = { 9b d1 [2] bf df [2] 94 f3 [2] ba d1 [2] ae ca [2] a1 d0 [2] bf cd [2] bd cc [2] a6 ca [2] ba cd [2] a6 e2 }

  condition:
    any of them
}