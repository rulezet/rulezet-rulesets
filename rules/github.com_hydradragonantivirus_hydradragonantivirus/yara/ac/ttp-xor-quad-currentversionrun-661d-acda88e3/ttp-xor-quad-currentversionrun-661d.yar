rule TTP_XOR_QUAD_CurrentVersionRun_661d {
  strings:
    $key_661d = { 35 72 [2] 11 7c [2] 3a 50 [2] 14 72 [2] 00 69 [2] 0f 73 [2] 11 6e [2] 13 6f [2] 08 69 [2] 14 6e [2] 08 41 }

  condition:
    any of them
}