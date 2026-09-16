rule TTP_XOR_QUAD_CurrentVersionRun_cbb3 {
  strings:
    $key_cbb3 = { 98 dc [2] bc d2 [2] 97 fe [2] b9 dc [2] ad c7 [2] a2 dd [2] bc c0 [2] be c1 [2] a5 c7 [2] b9 c0 [2] a5 ef }

  condition:
    any of them
}