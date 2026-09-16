rule TTP_XOR_QUAD_CurrentVersionRun_c9d4 {
  strings:
    $key_c9d4 = { 9a bb [2] be b5 [2] 95 99 [2] bb bb [2] af a0 [2] a0 ba [2] be a7 [2] bc a6 [2] a7 a0 [2] bb a7 [2] a7 88 }

  condition:
    any of them
}