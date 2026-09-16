rule TTP_XOR_QUAD_CurrentVersionRun_55eb {
  strings:
    $key_55eb = { 06 84 [2] 22 8a [2] 09 a6 [2] 27 84 [2] 33 9f [2] 3c 85 [2] 22 98 [2] 20 99 [2] 3b 9f [2] 27 98 [2] 3b b7 }

  condition:
    any of them
}