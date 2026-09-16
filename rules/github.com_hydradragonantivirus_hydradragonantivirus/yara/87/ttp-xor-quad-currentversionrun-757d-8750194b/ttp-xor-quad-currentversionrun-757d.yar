rule TTP_XOR_QUAD_CurrentVersionRun_757d {
  strings:
    $key_757d = { 26 12 [2] 02 1c [2] 29 30 [2] 07 12 [2] 13 09 [2] 1c 13 [2] 02 0e [2] 00 0f [2] 1b 09 [2] 07 0e [2] 1b 21 }

  condition:
    any of them
}