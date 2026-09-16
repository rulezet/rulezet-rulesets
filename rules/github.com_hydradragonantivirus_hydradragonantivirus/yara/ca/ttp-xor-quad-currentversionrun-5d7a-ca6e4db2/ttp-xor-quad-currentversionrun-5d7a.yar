rule TTP_XOR_QUAD_CurrentVersionRun_5d7a {
  strings:
    $key_5d7a = { 0e 15 [2] 2a 1b [2] 01 37 [2] 2f 15 [2] 3b 0e [2] 34 14 [2] 2a 09 [2] 28 08 [2] 33 0e [2] 2f 09 [2] 33 26 }

  condition:
    any of them
}