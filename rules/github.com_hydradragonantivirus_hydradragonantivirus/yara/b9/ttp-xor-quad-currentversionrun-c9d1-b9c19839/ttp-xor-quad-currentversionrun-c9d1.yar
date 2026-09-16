rule TTP_XOR_QUAD_CurrentVersionRun_c9d1 {
  strings:
    $key_c9d1 = { 9a be [2] be b0 [2] 95 9c [2] bb be [2] af a5 [2] a0 bf [2] be a2 [2] bc a3 [2] a7 a5 [2] bb a2 [2] a7 8d }

  condition:
    any of them
}