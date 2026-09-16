rule TTP_XOR_QUAD_CurrentVersionRun_c9ce {
  strings:
    $key_c9ce = { 9a a1 [2] be af [2] 95 83 [2] bb a1 [2] af ba [2] a0 a0 [2] be bd [2] bc bc [2] a7 ba [2] bb bd [2] a7 92 }

  condition:
    any of them
}