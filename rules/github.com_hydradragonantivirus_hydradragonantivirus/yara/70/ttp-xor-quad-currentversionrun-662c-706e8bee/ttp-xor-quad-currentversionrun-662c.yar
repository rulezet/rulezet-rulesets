rule TTP_XOR_QUAD_CurrentVersionRun_662c {
  strings:
    $key_662c = { 35 43 [2] 11 4d [2] 3a 61 [2] 14 43 [2] 00 58 [2] 0f 42 [2] 11 5f [2] 13 5e [2] 08 58 [2] 14 5f [2] 08 70 }

  condition:
    any of them
}