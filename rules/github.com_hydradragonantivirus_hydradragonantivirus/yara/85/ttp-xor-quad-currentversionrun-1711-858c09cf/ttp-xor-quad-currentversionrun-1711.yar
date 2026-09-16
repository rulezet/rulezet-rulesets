rule TTP_XOR_QUAD_CurrentVersionRun_1711 {
  strings:
    $key_1711 = { 44 7e [2] 60 70 [2] 4b 5c [2] 65 7e [2] 71 65 [2] 7e 7f [2] 60 62 [2] 62 63 [2] 79 65 [2] 65 62 [2] 79 4d }

  condition:
    any of them
}