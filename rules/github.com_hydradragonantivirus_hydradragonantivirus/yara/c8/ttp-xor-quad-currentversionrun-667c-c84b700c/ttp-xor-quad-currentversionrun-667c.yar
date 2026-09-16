rule TTP_XOR_QUAD_CurrentVersionRun_667c {
  strings:
    $key_667c = { 35 13 [2] 11 1d [2] 3a 31 [2] 14 13 [2] 00 08 [2] 0f 12 [2] 11 0f [2] 13 0e [2] 08 08 [2] 14 0f [2] 08 20 }

  condition:
    any of them
}