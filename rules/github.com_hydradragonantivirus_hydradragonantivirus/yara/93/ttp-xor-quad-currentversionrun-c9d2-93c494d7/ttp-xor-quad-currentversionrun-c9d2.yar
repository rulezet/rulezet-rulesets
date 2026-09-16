rule TTP_XOR_QUAD_CurrentVersionRun_c9d2 {
  strings:
    $key_c9d2 = { 9a bd [2] be b3 [2] 95 9f [2] bb bd [2] af a6 [2] a0 bc [2] be a1 [2] bc a0 [2] a7 a6 [2] bb a1 [2] a7 8e }

  condition:
    any of them
}