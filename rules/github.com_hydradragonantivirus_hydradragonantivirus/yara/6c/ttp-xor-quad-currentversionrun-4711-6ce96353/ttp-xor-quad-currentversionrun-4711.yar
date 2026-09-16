rule TTP_XOR_QUAD_CurrentVersionRun_4711 {
  strings:
    $key_4711 = { 14 7e [2] 30 70 [2] 1b 5c [2] 35 7e [2] 21 65 [2] 2e 7f [2] 30 62 [2] 32 63 [2] 29 65 [2] 35 62 [2] 29 4d }

  condition:
    any of them
}