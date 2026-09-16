rule TTP_XOR_QUAD_CurrentVersionRun_f711 {
  strings:
    $key_f711 = { a4 7e [2] 80 70 [2] ab 5c [2] 85 7e [2] 91 65 [2] 9e 7f [2] 80 62 [2] 82 63 [2] 99 65 [2] 85 62 [2] 99 4d }

  condition:
    any of them
}