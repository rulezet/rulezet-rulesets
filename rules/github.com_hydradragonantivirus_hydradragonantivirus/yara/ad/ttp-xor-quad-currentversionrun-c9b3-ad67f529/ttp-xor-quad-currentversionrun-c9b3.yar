rule TTP_XOR_QUAD_CurrentVersionRun_c9b3 {
  strings:
    $key_c9b3 = { 9a dc [2] be d2 [2] 95 fe [2] bb dc [2] af c7 [2] a0 dd [2] be c0 [2] bc c1 [2] a7 c7 [2] bb c0 [2] a7 ef }

  condition:
    any of them
}