rule TTP_XOR_QUAD_CurrentVersionRun_5711 {
  strings:
    $key_5711 = { 04 7e [2] 20 70 [2] 0b 5c [2] 25 7e [2] 31 65 [2] 3e 7f [2] 20 62 [2] 22 63 [2] 39 65 [2] 25 62 [2] 39 4d }

  condition:
    any of them
}