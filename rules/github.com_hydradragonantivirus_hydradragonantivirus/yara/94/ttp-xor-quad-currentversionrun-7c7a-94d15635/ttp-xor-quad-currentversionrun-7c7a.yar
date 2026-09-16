rule TTP_XOR_QUAD_CurrentVersionRun_7c7a {
  strings:
    $key_7c7a = { 2f 15 [2] 0b 1b [2] 20 37 [2] 0e 15 [2] 1a 0e [2] 15 14 [2] 0b 09 [2] 09 08 [2] 12 0e [2] 0e 09 [2] 12 26 }

  condition:
    any of them
}