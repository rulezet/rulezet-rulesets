rule TTP_XOR_QUAD_CurrentVersionRun_6600 {
  strings:
    $key_6600 = { 35 6f [2] 11 61 [2] 3a 4d [2] 14 6f [2] 00 74 [2] 0f 6e [2] 11 73 [2] 13 72 [2] 08 74 [2] 14 73 [2] 08 5c }

  condition:
    any of them
}