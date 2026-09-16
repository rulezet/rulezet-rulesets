rule TTP_XOR_QUAD_CurrentVersionRun_661a {
  strings:
    $key_661a = { 35 75 [2] 11 7b [2] 3a 57 [2] 14 75 [2] 00 6e [2] 0f 74 [2] 11 69 [2] 13 68 [2] 08 6e [2] 14 69 [2] 08 46 }

  condition:
    any of them
}