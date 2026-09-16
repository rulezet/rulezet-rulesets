rule TTP_XOR_QUAD_CurrentVersionRun_667d {
  strings:
    $key_667d = { 35 12 [2] 11 1c [2] 3a 30 [2] 14 12 [2] 00 09 [2] 0f 13 [2] 11 0e [2] 13 0f [2] 08 09 [2] 14 0e [2] 08 21 }

  condition:
    any of them
}