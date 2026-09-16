rule TTP_XOR_QUAD_CurrentVersionRun_7711 {
  strings:
    $key_7711 = { 24 7e [2] 00 70 [2] 2b 5c [2] 05 7e [2] 11 65 [2] 1e 7f [2] 00 62 [2] 02 63 [2] 19 65 [2] 05 62 [2] 19 4d }

  condition:
    any of them
}