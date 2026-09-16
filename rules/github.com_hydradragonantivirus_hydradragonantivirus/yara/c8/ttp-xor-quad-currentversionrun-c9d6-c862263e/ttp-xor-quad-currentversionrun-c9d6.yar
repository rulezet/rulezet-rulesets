rule TTP_XOR_QUAD_CurrentVersionRun_c9d6 {
  strings:
    $key_c9d6 = { 9a b9 [2] be b7 [2] 95 9b [2] bb b9 [2] af a2 [2] a0 b8 [2] be a5 [2] bc a4 [2] a7 a2 [2] bb a5 [2] a7 8a }

  condition:
    any of them
}