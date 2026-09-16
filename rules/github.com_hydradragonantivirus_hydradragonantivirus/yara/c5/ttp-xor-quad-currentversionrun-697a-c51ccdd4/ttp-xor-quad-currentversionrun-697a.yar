rule TTP_XOR_QUAD_CurrentVersionRun_697a {
  strings:
    $key_697a = { 3a 15 [2] 1e 1b [2] 35 37 [2] 1b 15 [2] 0f 0e [2] 00 14 [2] 1e 09 [2] 1c 08 [2] 07 0e [2] 1b 09 [2] 07 26 }

  condition:
    any of them
}