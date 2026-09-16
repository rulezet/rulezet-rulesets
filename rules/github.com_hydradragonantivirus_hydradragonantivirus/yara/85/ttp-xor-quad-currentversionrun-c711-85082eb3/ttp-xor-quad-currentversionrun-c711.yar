rule TTP_XOR_QUAD_CurrentVersionRun_c711 {
  strings:
    $key_c711 = { 94 7e [2] b0 70 [2] 9b 5c [2] b5 7e [2] a1 65 [2] ae 7f [2] b0 62 [2] b2 63 [2] a9 65 [2] b5 62 [2] a9 4d }

  condition:
    any of them
}