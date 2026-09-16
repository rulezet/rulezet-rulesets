rule TTP_XOR_QUAD_CurrentVersionRun_e0b3 {
  strings:
    $key_e0b3 = { b3 dc [2] 97 d2 [2] bc fe [2] 92 dc [2] 86 c7 [2] 89 dd [2] 97 c0 [2] 95 c1 [2] 8e c7 [2] 92 c0 [2] 8e ef }

  condition:
    any of them
}