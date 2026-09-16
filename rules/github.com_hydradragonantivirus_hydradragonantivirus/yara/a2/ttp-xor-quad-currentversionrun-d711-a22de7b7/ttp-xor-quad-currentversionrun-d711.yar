rule TTP_XOR_QUAD_CurrentVersionRun_d711 {
  strings:
    $key_d711 = { 84 7e [2] a0 70 [2] 8b 5c [2] a5 7e [2] b1 65 [2] be 7f [2] a0 62 [2] a2 63 [2] b9 65 [2] a5 62 [2] b9 4d }

  condition:
    any of them
}