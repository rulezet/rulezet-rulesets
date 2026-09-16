rule TTP_XOR_QUAD_CurrentVersionRun_557a {
  strings:
    $key_557a = { 06 15 [2] 22 1b [2] 09 37 [2] 27 15 [2] 33 0e [2] 3c 14 [2] 22 09 [2] 20 08 [2] 3b 0e [2] 27 09 [2] 3b 26 }

  condition:
    any of them
}