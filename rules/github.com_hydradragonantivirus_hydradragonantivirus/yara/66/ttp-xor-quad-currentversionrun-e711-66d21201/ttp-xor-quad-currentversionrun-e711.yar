rule TTP_XOR_QUAD_CurrentVersionRun_e711 {
  strings:
    $key_e711 = { b4 7e [2] 90 70 [2] bb 5c [2] 95 7e [2] 81 65 [2] 8e 7f [2] 90 62 [2] 92 63 [2] 89 65 [2] 95 62 [2] 89 4d }

  condition:
    any of them
}