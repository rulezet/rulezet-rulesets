rule TTP_XOR_QUAD_CurrentVersionRun_e0b2 {
  strings:
    $key_e0b2 = { b3 dd [2] 97 d3 [2] bc ff [2] 92 dd [2] 86 c6 [2] 89 dc [2] 97 c1 [2] 95 c0 [2] 8e c6 [2] 92 c1 [2] 8e ee }

  condition:
    any of them
}